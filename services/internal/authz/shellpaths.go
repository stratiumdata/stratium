package authz

import "strings"

// shellSeparators are the characters that end one command word or one command
// and begin another. They are blanked to spaces before tokenizing so a path
// adjacent to a separator -- `cat /a;cat /b`, `echo x >/secret/out` -- is
// still its own token. Blanking rather than parsing is deliberate: this is a
// matching aid, not a shell, and every construct it does not understand
// degrades toward MORE tokens, which is the safe direction (see
// ShellResourceIDs' own doc comment).
const shellSeparators = ";|&`()<>\n\r"

// ShellResourceIDs returns every path-like token in a shell command, in source
// order, deduplicated.
//
// It exists because a tool catalogued with a command_field and no
// resource_field produces no resource identity at all, so a classification cap
// denies its every call permanently -- J1 in docs/validation-journeys.md, and
// proven live at TestIntegration_Journey1_AClassificationCapDeniesEvery
// FieldlessToolCall.
//
// # Why EVERY path, and not the first one
//
// internal/pdpgrpc/label.go states the premise that makes labelling an
// agent-influenced identifier safe at all (R4):
//
//	the id is what the tool actually acts on. Naming a different resource
//	changes what you get, not merely what you are permitted; lying does not
//	pay.
//
// For Read(file_path) that holds exactly. For a shell command it holds only if
// every path the command names is accounted for. Extracting just the first one
// from
//
//	cat /tmp/notes.txt; cat /secret/plans.txt
//
// yields /tmp/notes.txt, which a catch-all rule labels UNCLASSIFIED, while the
// command still reads the secret -- lying pays, and it pays better than the
// status quo, because it converts a loud denial into a silent allow. Returning
// every path and letting the caller take the STRICTEST label restores the
// premise: a decoy only ever adds constraints, and the real target cannot be
// omitted because the command needs it to run.
//
// # Why the bias is toward including a doubtful token
//
// The two failure directions are not symmetric.
//
// Over-extraction is inert. A token that is not really a path still resolves
// under the empty-prefix catch-all that any capped tenant is already required
// to have -- SetAgentClassificationCaps refuses a cap without one
// (ErrNoCatchAllRule) -- so it contributes the floor level and changes
// nothing. That interlock is load-bearing, not incidental: without a
// catch-all, labelResource's fold treats an unresolvable member as
// unrankable and denies, and every flag token would deny the call.
//
// Under-extraction is a silent weakening. A path form this function misses
// contributes nothing to the fold and can lower the effective classification
// below the truth, which is exactly the R4 failure above.
//
// So any future edit that makes this function MORE selective is arguing
// against this paragraph and should say so explicitly.
//
// # What it deliberately is not
//
// Not a shell parser. Variable expansion, here-documents, and base64-piped-to-
// sh all defeat it, the same way they defeat the tier classifier next door --
// see tier.go's RESIDUAL RISK note, which applies here verbatim. The controls
// that actually hold are the delegation ceiling, the agent allowlist, and
// escalation. This function's job is to stop a resource being *accidentally*
// or *casually* unlabelled, not to withstand a determined attacker.
func ShellResourceIDs(command string) []string {
	if command == "" {
		return nil
	}

	// normalizeCommand is shared with the tier classifier on purpose: an
	// adversary must not be able to hide a path from the labeller by spelling
	// it in a way the tier classifier already sees through.
	blanked := strings.Map(func(r rune) rune {
		if strings.ContainsRune(shellSeparators, r) {
			return ' '
		}
		return r
	}, normalizeCommand(command))

	var ids []string
	seen := make(map[string]bool)
	for _, field := range strings.Fields(blanked) {
		// Split on '=' so a flag carrying a path (--file=/secret/x) yields
		// the path rather than the whole token, which would match no
		// prefix rule and quietly contribute nothing.
		for _, part := range strings.Split(field, "=") {
			part = strings.Trim(part, "$'\"")
			if !looksLikePath(part) || seen[part] {
				continue
			}
			seen[part] = true
			ids = append(ids, part)
		}
	}
	return ids
}

// looksLikePath reports whether a token is plausibly a resource identity.
//
// Three shapes, chosen because each is one a tenant's prefix rules can
// actually match: anything containing a separator, anything home-relative,
// and a bare name carrying a short extension. A token matching none of them
// -- a subcommand, a flag, a bare word -- cannot match a prefix rule anyway,
// so including it would add noise without adding safety.
func looksLikePath(s string) bool {
	if s == "" {
		return false
	}
	if strings.Contains(s, "/") || strings.HasPrefix(s, "~") {
		return true
	}
	dot := strings.LastIndex(s, ".")
	if dot <= 0 || dot == len(s)-1 {
		return false
	}
	ext := s[dot+1:]
	if len(ext) > 8 {
		return false
	}
	for _, r := range ext {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}
