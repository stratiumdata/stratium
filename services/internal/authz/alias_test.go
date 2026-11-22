package authz

import (
	"slices"
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
		{"a patch field is carried as the patch, not as a command",
			ToolAlias{Canonical: "Bash", PatchField: "cmd"}, nil,
			ExtractedInput{Cataloged: true, Patch: "ls -la"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExtractAliased(tt.rows, a, tt.alias, "/cwd"); got != tt.want {
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
		a, _ = ApplyExtraction(ExtractAliased(nil, a, alias, ""), a, nil)
		got, err := DeriveTier(TierTable{Catalog: DefaultCatalog()}, a)
		if err != nil || got != want {
			t.Errorf("%q: tier = %v, err = %v, want %v", cmd, got, err, want)
		}
	}
}

func TestPatchResourceIDs(t *testing.T) {
	tests := []struct {
		name, patch, cwd string
		want             []string
	}{
		{"every kind of header, relative to cwd, in order, once each",
			"*** Begin Patch\n*** Add File: a.txt\n+hi\n*** Update File: src/b.go\n*** Move to: src/c.go\n@@\n-x\n+y\n" +
				"*** Delete File: a.txt\n*** Delete File: /etc/d\n*** End Patch",
			"/work", []string{"/work/a.txt", "/work/src/b.go", "/work/src/c.go", "/etc/d"}},
		{"a relative path that climbs is refused, not resolved", "*** Update File: ../../etc/shadow", "/work/sub", nil},
		{"so is an absolute one", "*** Add File: /work/a.txt\n*** Update File: /work/x/../../etc/passwd", "/work", nil},
		{"and a cwd that climbs", "*** Update File: a.txt", "/work/../etc", nil},
		{"dots that are not a segment are just a name", "*** Update File: ./a..b/..c", "/work//", []string{"/work/a..b/..c"}},
		{"indented headers and CRLF, as Codex accepts them",
			"*** Begin Patch\r\n  *** Update File: a.txt \r\n", "/work", []string{"/work/a.txt"}},
		{"file content that reads like a header counts too",
			"*** Update File: a.txt\n+*** not this\n *** Delete File: b.txt", "/work", []string{"/work/a.txt", "/work/b.txt"}},
		{"absolute paths need no cwd", "*** Add File: /work/a.txt", "", []string{"/work/a.txt"}},
		{"a relative path with no cwd is not guessed at", "*** Add File: /work/a.txt\n*** Add File: b.txt", "", nil},
		{"nor with a relative cwd", "*** Add File: b.txt", "work", nil},
		{"no headers", "*** Begin Patch\n*** End Patch", "/work", nil},
		{"empty", "", "/work", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PatchResourceIDs(tt.patch, tt.cwd); !slices.Equal(got, tt.want) {
				t.Errorf("PatchResourceIDs() = %q, want %q", got, tt.want)
			}
		})
	}
}

// A tier the tenant set on the name as sent survives the alias, and only as
// a raise.
func TestRaiseForWireName(t *testing.T) {
	base := TierTable{Catalog: DefaultCatalog()} // Edit is INTERNAL_MODIFY
	aliased := Action{Tool: "Edit", WireTool: "apply_patch"}
	tests := []struct {
		name   string
		stored map[string]models.ActionTier
		action Action
		want   models.ActionTier
	}{
		{"a higher tier on the wire name raises", map[string]models.ActionTier{"apply_patch": models.ActionTierDestructive}, aliased, models.ActionTierDestructive},
		{"a lower one does not lower", map[string]models.ActionTier{"apply_patch": models.ActionTierReadOnly}, aliased, models.ActionTierInternalModify},
		{"none", nil, aliased, models.ActionTierInternalModify},
		{"a call that was not aliased is untouched", map[string]models.ActionTier{"": models.ActionTierDestructive}, Action{Tool: "Edit"}, models.ActionTierInternalModify},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DeriveTier(RaiseForWireName(base, tt.stored, tt.action), tt.action)
			if err != nil || got != tt.want {
				t.Errorf("tier = %v, err = %v, want %v", got, err, tt.want)
			}
		})
	}
	if base.Overrides != nil {
		t.Error("RaiseForWireName altered the table it was given")
	}
}

func TestResolveFilePath(t *testing.T) {
	tests := []struct {
		p, cwd, want string
		ok           bool
	}{
		{"README.md", "/work", "/work/README.md", true},
		{"./src//a.go", "/work/", "/work/src/a.go", true},
		{"/abs/a.go", "", "/abs/a.go", true},
		{"a..b/..c", "/work", "/work/a..b/..c", true},
		{"README.md", "", "", false},
		{"README.md", "work", "", false},
		{"../x", "/work", "", false},
		{"/work/a/../../etc/passwd", "/work", "", false},
		{"a.txt", "/work/../etc", "", false},
		{"~", "/work", "", false},
		{"~/notes.txt", "/work", "", false},
		{"~user.txt", "/work", "/work/~user.txt", true},
		{"", "/work", "", false},
	}
	for _, tt := range tests {
		if got, ok := ResolveFilePath(tt.p, tt.cwd); got != tt.want || ok != tt.ok {
			t.Errorf("ResolveFilePath(%q, %q) = %q, %v; want %q, %v", tt.p, tt.cwd, got, ok, tt.want, tt.ok)
		}
	}
}

// OpenCode 2.x tool calls, decided as the canonical tools. The read, edit,
// write and shell inputs have the shape captured from a live OpenCode 2.3.2
// session (relative paths, these field names); the rest are built from its
// tool schemas (packages/core/src/tool/plugin).
func TestOpenCodeAliases(t *testing.T) {
	tests := []struct {
		tool, input   string
		wantTool      string
		wantID        string
		wantCommand   string
		wantPatchIDs  []string
		wantTier      models.ActionTier
		wantNoAliasAt bool
	}{
		{tool: "shell", input: `{"command":"git status","workdir":"/work","timeout":120000}`,
			wantTool: "Bash", wantCommand: "git status", wantTier: models.ActionTierReadOnly},
		{tool: "shell", input: `{"command":"rm -rf build"}`,
			wantTool: "Bash", wantCommand: "rm -rf build", wantTier: models.ActionTierDestructive},
		{tool: "read", input: `{"path":"README.md","offset":1,"limit":50}`,
			wantTool: "Read", wantID: "/work/README.md", wantTier: models.ActionTierReadOnly},
		{tool: "write", input: `{"path":"/work/out.txt","content":"x"}`,
			wantTool: "Write", wantID: "/work/out.txt", wantTier: models.ActionTierInternalModify},
		{tool: "edit", input: `{"path":"src/a.go","oldString":"a","newString":"b"}`,
			wantTool: "Edit", wantID: "/work/src/a.go", wantTier: models.ActionTierInternalModify},
		{tool: "edit", input: `{"path":"~/notes/todo.md","oldString":"a","newString":"b"}`,
			wantTool: "Edit", wantID: "", wantTier: models.ActionTierInternalModify},
		{tool: "patch", input: `{"patchText":"*** Begin Patch\n*** Add File: n.txt\n+hi\n*** End Patch"}`,
			wantTool: "Edit", wantPatchIDs: []string{"/work/n.txt"}, wantTier: models.ActionTierInternalModify},
		{tool: "glob", input: `{"pattern":"**/*.go"}`, wantTool: "Glob", wantTier: models.ActionTierReadOnly},
		{tool: "grep", input: `{"pattern":"TODO","path":"src"}`, wantTool: "Grep", wantTier: models.ActionTierReadOnly},
		{tool: "webfetch", input: `{"url":"https://example.com","format":"markdown"}`, wantTool: "WebFetch", wantTier: models.ActionTierReadOnly},
		{tool: "websearch", input: `{"query":"x"}`, wantTool: "WebSearch", wantTier: models.ActionTierReadOnly},
		// Code Mode, subagents and MCP tools keep their own names.
		{tool: "execute", input: `{}`, wantNoAliasAt: true},
		{tool: "subagent", input: `{}`, wantNoAliasAt: true},
		{tool: "github_create_issue", input: `{}`, wantNoAliasAt: true},
		// Claude Code's names are not OpenCode's: sent by this harness they
		// are somebody else's tools.
		{tool: "Bash", input: `{"command":"ls"}`, wantNoAliasAt: true},
	}
	for _, tt := range tests {
		t.Run(tt.tool+" "+tt.input, func(t *testing.T) {
			a, alias := ResolveAlias("opencode", nil, Action{Tool: tt.tool, RawInput: tt.input})
			if tt.wantNoAliasAt {
				if alias != nil || a.Tool != tt.tool {
					t.Fatalf("aliased to %q, want no alias", a.Tool)
				}
				return
			}
			if alias == nil || a.Tool != tt.wantTool || a.WireTool != tt.tool {
				t.Fatalf("Tool = %q, WireTool = %q, alias = %v; want %q", a.Tool, a.WireTool, alias, tt.wantTool)
			}
			ext := ExtractAliased(nil, a, *alias, "/work")
			if ext.ResourceID != tt.wantID || ext.Command != tt.wantCommand {
				t.Errorf("ResourceID = %q, Command = %q; want %q, %q", ext.ResourceID, ext.Command, tt.wantID, tt.wantCommand)
			}
			if got := PatchResourceIDs(ext.Patch, "/work"); !slices.Equal(got, tt.wantPatchIDs) {
				t.Errorf("patch ids = %q, want %q", got, tt.wantPatchIDs)
			}
			a, _ = ApplyExtraction(ext, a, nil)
			if tier, err := DeriveTier(TierTable{Catalog: DefaultCatalog()}, a); err != nil || tier != tt.wantTier {
				t.Errorf("tier = %v, err = %v, want %v", tier, err, tt.wantTier)
			}
		})
	}
}
