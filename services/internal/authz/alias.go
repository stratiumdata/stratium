package authz

import (
	"encoding/json"
	"maps"
	"path"
	"strings"

	"github.com/stratiumdata/stratium/pkg/models"
)

// ToolAlias says which canonical tool a harness's own tool name stands for,
// and where in that harness's input the command or the resource identity
// lives. An empty field name means "this input carries none".
//
// A resource identity comes from one of three fields. ResourceField is taken
// as written. PathField holds one file path, which is resolved against the
// caller's working directory (ResolveFilePath): harnesses that send relative
// paths would otherwise name a different resource than the one they touch.
// PatchField holds a patch whose text names the files (PatchResourceIDs); it
// is WholeInput when the tool's input is the patch text itself.
type ToolAlias struct {
	Canonical     string
	CommandField  string
	ResourceField string
	PathField     string
	PatchField    string
}

// WholeInput, as a PatchField, says the tool's input is not an object with a
// field to read but one JSON string, and that string is the value.
const WholeInput = "."

// NamesFiles reports whether calls through this alias say which files they
// touch. One that does and yields no file is refused (pdpgrpc.Decide).
func (t ToolAlias) NamesFiles() bool { return t.PathField != "" || t.PatchField != "" }

// DefaultAliases is the built-in table: harness, then that harness's own tool
// name. The canonical names are DefaultCatalog's (Claude Code's), so a
// policy, a tool list or a tier override written for "Bash" or "Edit" covers
// the same tool under every harness listed here.
//
// "claude" has no rows: its names are the canonical ones. Codex already
// reports its shell tool as "Bash" with a "command" field, so it needs only
// the one row.
//
// A fresh map per call, like DefaultCatalog, so no caller can alter another's.
func DefaultAliases() map[string]map[string]ToolAlias {
	return map[string]map[string]ToolAlias{
		"codex": {
			// Codex hands a hook the patch text as "command". It is not a
			// shell command, so it is not a CommandField.
			"apply_patch": {Canonical: "Edit", PatchField: "command"},
		},
		// OpenCode 2.x. Fields mirror what the Claude Code catalog seed gives
		// the canonical tool: a file path for the three file tools, nothing
		// for search and web. Its other tools (todo, question, skill,
		// subagent, execute) and MCP tools have no alias and are decided
		// under their own names.
		"opencode": {
			"shell":     {Canonical: "Bash", CommandField: "command"},
			"read":      {Canonical: "Read", PathField: "path"},
			"write":     {Canonical: "Write", PathField: "path"},
			"edit":      {Canonical: "Edit", PathField: "path"},
			"patch":     {Canonical: "Edit", PatchField: "patchText"},
			"glob":      {Canonical: "Glob"},
			"grep":      {Canonical: "Grep"},
			"webfetch":  {Canonical: "WebFetch"},
			"websearch": {Canonical: "WebSearch"},
		},
		// Cursor, from live sessions of its CLI (2026.11.19). Read and Write
		// carry Claude Code's names but are Cursor's own tools, so they get
		// rows too: the row, not a tenant's catalog entry for the canonical
		// tool, says where the path is, and a call without it is refused.
		// An edit of an existing file arrives as Write. Delete has no
		// canonical tool: it keeps its name and gains its file's identity.
		// Grep (which also finds files), WebFetch and WebSearch carry no
		// resource under either name and need no row. Task and MCP:<tool>
		// are decided under their own names.
		"cursor": {
			"Shell":  {Canonical: "Bash", CommandField: "command"},
			"Read":   {Canonical: "Read", PathField: "file_path"},
			"Write":  {Canonical: "Write", PathField: "file_path"},
			"Delete": {Canonical: "Delete", PathField: "file_path"},
		},
		// Copilot CLI, by the names its camelCase hook events carry. bash,
		// view, apply_patch, rg and glob are from live sessions (1.0.114):
		// which file tool a session has depends on its model, and the ones
		// seen used apply_patch, whose input is the patch text itself, for
		// every edit and new file. create, edit and str_replace_editor are
		// from Copilot's documentation, with "path" assumed; a call without
		// it is refused. Search and web tools carry no resource, as their
		// canonical tools do. Everything else keeps its own name.
		"copilot": {
			"bash":               {Canonical: "Bash", CommandField: "command"},
			"view":               {Canonical: "Read", PathField: "path"},
			"create":             {Canonical: "Write", PathField: "path"},
			"edit":               {Canonical: "Edit", PathField: "path"},
			"str_replace_editor": {Canonical: "Edit", PathField: "path"},
			"apply_patch":        {Canonical: "Edit", PatchField: WholeInput},
			"grep":               {Canonical: "Grep"},
			"rg":                 {Canonical: "Grep"},
			"glob":               {Canonical: "Glob"},
			"web_fetch":          {Canonical: "WebFetch"},
			"web_search":         {Canonical: "WebSearch"},
		},
		// Antigravity CLI. It has two sets of tool names: the ones live
		// sessions of 1.5.14 sent (run_command, read_file, write_file,
		// edit_file, search_web) and the ones its documentation lists
		// (view_file, write_to_file, replace_file_content and the rest),
		// with different field names. Either may arrive, so both are here.
		// Subagent, task, MCP and browser tools keep their own names.
		// Kiro CLI's v3 engine, from live sessions of 3.5.0: execute_bash,
		// read_file, fs_write, str_replace, web_fetch and remote_web_search.
		// fs_append, delete_file, list_directory, file_search and grep_search
		// are from Kiro's documentation, with "path" assumed; a file call
		// without its path is refused. execute_pwsh, Kiro's shell on Windows,
		// has no row: PowerShell is not read as a Bash command, so it is
		// decided under its own name, as Copilot's powershell is.
		// delete_file has no canonical tool: it keeps its name and gains its
		// file's identity. code, tool_load, invoke_sub_agent and
		// mcp_<server>_<tool> are decided under their own names.
		"kiro": {
			"execute_bash":      {Canonical: "Bash", CommandField: "command"},
			"read_file":         {Canonical: "Read", PathField: "path"},
			"fs_write":          {Canonical: "Write", PathField: "path"},
			"fs_append":         {Canonical: "Edit", PathField: "path"},
			"str_replace":       {Canonical: "Edit", PathField: "path"},
			"delete_file":       {Canonical: "delete_file", PathField: "path"},
			"list_directory":    {Canonical: "LS", PathField: "path"},
			"file_search":       {Canonical: "Glob"},
			"grep_search":       {Canonical: "Grep"},
			"web_fetch":         {Canonical: "WebFetch"},
			"remote_web_search": {Canonical: "WebSearch"},
		},
		"antigravity": {
			"run_command":                {Canonical: "Bash", CommandField: "CommandLine"},
			"read_file":                  {Canonical: "Read", PathField: "Path"},
			"view_file":                  {Canonical: "Read", PathField: "AbsolutePath"},
			"write_file":                 {Canonical: "Write", PathField: "Path"},
			"write_to_file":              {Canonical: "Write", PathField: "TargetFile"},
			"edit_file":                  {Canonical: "Edit", PathField: "Path"},
			"replace_file_content":       {Canonical: "Edit", PathField: "TargetFile"},
			"multi_replace_file_content": {Canonical: "Edit", PathField: "TargetFile"},
			"list_dir":                   {Canonical: "LS", PathField: "DirectoryPath"},
			"find_by_name":               {Canonical: "Glob"},
			"grep_search":                {Canonical: "Grep"},
			"read_url_content":           {Canonical: "WebFetch"},
			"search_web":                 {Canonical: "WebSearch"},
		},
	}
}

// ResolveAlias renames a's tool to its canonical name when harness has an
// alias for it, and reports the alias that applied.
//
// It does nothing when harness is empty (every caller that is not a harness
// hook) or when the harness has no alias for the name.
//
// A tenant's own catalog row for the name as received does not displace the
// alias. A caller that names its harness has said whose tool this is, and a
// row with the same name was written for some other tool: the MCP filesystem
// server's read_file is not Antigravity CLI's, and the two put their path in
// different fields. Letting the row win would decide the harness's tool with
// another tool's extraction and no file identity. A higher tier on that row
// is still honoured (RaiseForWireName).
//
// A harness tool that already carries the canonical name is not renamed.
//
// The name as received is kept in WireTool, which is what gets recorded.
func ResolveAlias(harness string, a Action) (Action, *ToolAlias) {
	alias, ok := DefaultAliases()[harness][a.Tool]
	if !ok {
		return a, nil
	}
	if alias.Canonical == a.Tool {
		return a, &alias
	}
	a.WireTool = a.Tool
	a.Tool = alias.Canonical
	return a, &alias
}

// ExtractAliased is ExtractFromCatalog for a call an alias applied to. The
// verb is the canonical tool's, from the tenant's row for it when there is
// one. The command and the resource identity are read from the fields the
// alias names and from nowhere else: the canonical row's field names describe
// the canonical tool's input, not this harness's.
//
// The result is always Cataloged. The PDP knows what this tool is, so
// whatever resource the caller asserted is replaced, as it is for any
// cataloged tool.
func ExtractAliased(entries []models.ToolCatalogEntry, a Action, alias ToolAlias, cwd string) ExtractedInput {
	out := ExtractedInput{Cataloged: true, Verb: ExtractFromCatalog(entries, a).Verb}
	obj := parseJSONObject(a.RawInput)
	if alias.ResourceField != "" {
		out.ResourceID = jsonStringField(obj, alias.ResourceField)
	}
	if alias.CommandField != "" {
		out.Command = jsonStringField(obj, alias.CommandField)
	}
	if alias.PathField != "" {
		out.ResourceID, _ = ResolveFilePath(jsonStringField(obj, alias.PathField), cwd)
	}
	if alias.PatchField == WholeInput {
		_ = json.Unmarshal([]byte(a.RawInput), &out.Patch)
	} else if alias.PatchField != "" {
		out.Patch = jsonStringField(obj, alias.PatchField)
	}
	return out
}

// ResolveFilePath returns p as a clean absolute path, resolving a relative
// one against cwd. It reports false, and the caller refuses the call, when
// the path cannot be resolved from the text alone:
//
//   - it is empty, or relative and cwd is not absolute;
//   - it has a ".." segment, refused for the reason checkResourceConstraints
//     refuses it: through a symbolic link the file system's answer differs
//     from the one the text gives;
//   - it starts with "~", which some harnesses expand to a home directory
//     the PDP does not know.
//
// ponytail: forward-slash paths only. A Windows path is treated as relative.
func ResolveFilePath(p, cwd string) (string, bool) {
	p = strings.TrimSpace(p)
	if p == "" || p == "~" || strings.HasPrefix(p, "~/") {
		return "", false
	}
	if !path.IsAbs(p) {
		if !path.IsAbs(cwd) {
			return "", false
		}
		p = cwd + "/" + p
	}
	if hasDotDotSegment(p) {
		return "", false
	}
	return path.Clean(p), true
}

// patchFileMarkers start the lines of a patch that name a file. The format is
// the one Codex's apply_patch reads.
var patchFileMarkers = []string{"*** Add File: ", "*** Delete File: ", "*** Update File: ", "*** Move to: "}

// PatchResourceIDs returns every file a patch names, as clean absolute paths,
// in source order, deduplicated. A relative path is resolved against cwd.
//
// It returns nil when the patch names no file or names one ResolveFilePath
// cannot resolve: a path is not guessed at, and the caller refuses a patch
// it has no identities for.
//
// Every line is looked at, indented or not, so a line of file content that
// happens to read like a header is taken as a path too. Like ShellResourceIDs,
// the bias is toward too many: an extra path only adds constraints.
func PatchResourceIDs(patch, cwd string) []string {
	var ids []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(patch, "\n") {
		line = strings.TrimSpace(line)
		for _, marker := range patchFileMarkers {
			p, ok := strings.CutPrefix(line, marker)
			if !ok || strings.TrimSpace(p) == "" {
				continue
			}
			p, ok = ResolveFilePath(p, cwd)
			if !ok {
				return nil
			}
			if !seen[p] {
				seen[p] = true
				ids = append(ids, p)
			}
		}
	}
	return ids
}

// RaiseForWireName returns t with a's tier raised to the highest tier the
// tenant set on the name a arrived under, by a tier override or a catalog
// row, when that is higher. An alias moves the call to its canonical name; a
// tier the tenant set on the name as sent must not be lost on the way. Raise
// only, like every override.
func RaiseForWireName(t TierTable, stored map[string]models.ActionTier, entries []models.ToolCatalogEntry, a Action) TierTable {
	if a.WireTool == "" {
		return t
	}
	raise, ok := stored[a.WireTool]
	for _, e := range entries {
		if e.ToolName == a.WireTool && e.ActionTier != nil && (!ok || *e.ActionTier > raise) {
			raise, ok = *e.ActionTier, true
		}
	}
	if !ok {
		return t
	}
	if current, err := deriveTierByName(t, a); err != nil || raise <= current {
		return t
	}
	overrides := maps.Clone(t.Overrides)
	if overrides == nil {
		overrides = make(map[string]models.ActionTier, 1)
	}
	overrides[lookupKeys(a)[0]] = raise
	t.Overrides = overrides
	return t
}
