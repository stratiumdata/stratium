package authz

import "github.com/stratiumdata/stratium/pkg/models"

// ToolAlias says which canonical tool a harness's own tool name stands for,
// and where in that harness's input the command or the resource identity
// lives. An empty field name means "this input carries none".
type ToolAlias struct {
	Canonical     string
	CommandField  string
	ResourceField string
}

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
			// The files are named inside the patch text, not in a field, so
			// this carries no resource identity: under a path constraint the
			// call denies. See ResolveAlias.
			"apply_patch": {Canonical: "Edit"},
		},
	}
}

// ResolveAlias renames a's tool to its canonical name when harness has an
// alias for it, and reports the alias that applied.
//
// It does nothing when harness is empty (every caller that is not a harness
// hook), when the harness has no alias for the name, or when the tenant's
// own catalog has a row for the exact name as received: a tenant can always
// say what one of its tools is.
//
// The name as received is kept in WireTool, which is what gets recorded.
func ResolveAlias(harness string, entries []models.ToolCatalogEntry, a Action) (Action, *ToolAlias) {
	alias, ok := DefaultAliases()[harness][a.Tool]
	if !ok {
		return a, nil
	}
	for _, e := range entries {
		if e.ToolName == a.Tool {
			return a, nil
		}
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
func ExtractAliased(entries []models.ToolCatalogEntry, a Action, alias ToolAlias) ExtractedInput {
	out := ExtractedInput{Cataloged: true, Verb: ExtractFromCatalog(entries, a).Verb}
	obj := parseJSONObject(a.RawInput)
	if alias.ResourceField != "" {
		out.ResourceID = jsonStringField(obj, alias.ResourceField)
	}
	if alias.CommandField != "" {
		out.Command = jsonStringField(obj, alias.CommandField)
	}
	return out
}
