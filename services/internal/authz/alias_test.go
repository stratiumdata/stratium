package authz

import (
	"testing"

	"github.com/stratiumdata/stratium/pkg/models"
)

// ExtractAliased reads only the fields the alias names. The canonical tool's
// own catalog row supplies the verb and nothing else: its field names
// describe a different harness's input.
func TestExtractAliased(t *testing.T) {
	canonicalField := "file_path"
	entries := []models.ToolCatalogEntry{{ToolName: "Bash", Verb: "execute", ResourceField: &canonicalField}}
	a := Action{Tool: "Bash", WireTool: "run", RawInput: `{"cmd":"ls -la","dir":"/workspace","file_path":"/etc/shadow"}`}

	tests := []struct {
		name  string
		alias ToolAlias
		rows  []models.ToolCatalogEntry
		want  ExtractedInput
	}{
		{"fields named by the alias, verb from the canonical row",
			ToolAlias{Canonical: "Bash", CommandField: "cmd", ResourceField: "dir"}, entries,
			ExtractedInput{Cataloged: true, Verb: "execute", Command: "ls -la", ResourceID: "/workspace"}},
		{"works without a tenant row for the canonical tool",
			ToolAlias{Canonical: "Bash", CommandField: "cmd"}, nil,
			ExtractedInput{Cataloged: true, Command: "ls -la"}},
		{"no fields extracts nothing, not the canonical row's field",
			ToolAlias{Canonical: "Bash"}, entries,
			ExtractedInput{Cataloged: true, Verb: "execute"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExtractAliased(tt.rows, a, tt.alias); got != tt.want {
				t.Errorf("ExtractAliased() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// An aliased shell command is classified by its command, with or without a
// tenant row for the canonical tool: the alias is a complete extraction rule.
func TestAliasedCommandIsClassifiedByItsCommand(t *testing.T) {
	alias := ToolAlias{Canonical: "Bash", CommandField: "cmd"}
	for cmd, want := range map[string]models.ActionTier{
		"ls -la":   models.ActionTierReadOnly,
		"rm -rf /": models.ActionTierDestructive,
	} {
		a := Action{Tool: "Bash", WireTool: "run", RawInput: `{"cmd":"` + cmd + `"}`}
		a, _ = ApplyExtraction(ExtractAliased(nil, a, alias), a, nil)
		got, err := DeriveTier(TierTable{Catalog: DefaultCatalog()}, a)
		if err != nil || got != want {
			t.Errorf("%q: tier = %v, err = %v, want %v", cmd, got, err, want)
		}
	}
}
