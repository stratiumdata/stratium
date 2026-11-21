package authz

import (
	"maps"
	"path"
	"strings"

	"github.com/stratiumdata/stratium/pkg/models"
)

// ToolAlias says which canonical tool a harness's own tool name stands for,
// and where in that harness's input the command or the resource identity
// lives. An empty field name means "this input carries none".
//
// PatchField names a field holding a patch whose text names the files it
// touches (PatchResourceIDs).
type ToolAlias struct {
	Canonical     string
	CommandField  string
	ResourceField string
	PatchField    string
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
			// Codex hands a hook the patch text as "command". It is not a
			// shell command, so it is not a CommandField.
			"apply_patch": {Canonical: "Edit", PatchField: "command"},
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
	if alias.PatchField != "" {
		out.Patch = jsonStringField(obj, alias.PatchField)
	}
	return out
}

// patchFileMarkers start the lines of a patch that name a file. The format is
// the one Codex's apply_patch reads.
var patchFileMarkers = []string{"*** Add File: ", "*** Delete File: ", "*** Update File: ", "*** Move to: "}

// PatchResourceIDs returns every file a patch names, as clean absolute paths,
// in source order, deduplicated. A relative path is resolved against cwd.
//
// It returns nil when the patch names no file, names a relative one and cwd
// is not absolute, or any path has a ".." segment: a path that cannot be
// resolved is not guessed at, and the caller refuses a patch it has no
// identities for. ".." is refused, not resolved, for the reason
// checkResourceConstraints refuses it: through a symbolic link the file
// system's answer differs from the one the text gives.
//
// Every line is looked at, indented or not, so a line of file content that
// happens to read like a header is taken as a path too. Like ShellResourceIDs,
// the bias is toward too many: an extra path only adds constraints.
//
// ponytail: forward-slash paths only. A Windows path is treated as relative.
func PatchResourceIDs(patch, cwd string) []string {
	var ids []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(patch, "\n") {
		line = strings.TrimSpace(line)
		for _, marker := range patchFileMarkers {
			p, ok := strings.CutPrefix(line, marker)
			if p = strings.TrimSpace(p); !ok || p == "" {
				continue
			}
			if !path.IsAbs(p) {
				if !path.IsAbs(cwd) {
					return nil
				}
				p = cwd + "/" + p
			}
			if hasDotDotSegment(p) {
				return nil
			}
			if p = path.Clean(p); !seen[p] {
				seen[p] = true
				ids = append(ids, p)
			}
		}
	}
	return ids
}

// RaiseForWireName returns t with a's tier raised to the tenant's override
// for the name a arrived under, when there is one and it is higher. An alias
// moves the call to its canonical name; a tier the tenant set on the name as
// sent must not be lost on the way. Raise only, like every override.
func RaiseForWireName(t TierTable, stored map[string]models.ActionTier, a Action) TierTable {
	raise, ok := stored[a.WireTool]
	if a.WireTool == "" || !ok {
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
