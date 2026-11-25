package authz

import (
	"path"
	"strings"
)

// The id_prefix constraint is stricter about a shell command than labelling
// is, and the two must not share a word list. A label takes the strictest of
// every word, so an extra word is harmless there. id_prefix needs EVERY word
// inside the prefix, so the extra words below are checked only for it.
//
// ponytail: a word list and a quote scan, not a shell parser. Commands outside
// fileCommands, an interpreter running a script, and symlinks still reach
// outside the prefix. To confine a shell, run it in a sandbox.

// fileCommands are commands whose every non-flag argument names a file or
// directory. A command with a pattern or mode argument (grep, sed, chmod) is
// deliberately absent: its first operand is not a path, and treating it as one
// would deny every use.
var fileCommands = map[string]bool{
	"cat": true, "ls": true, "cd": true, "pushd": true, "rm": true, "rmdir": true,
	"cp": true, "mv": true, "ln": true, "touch": true, "mkdir": true,
	"head": true, "tail": true, "less": true, "more": true, "tac": true, "nl": true,
	"stat": true, "du": true, "wc": true, "file": true, "tee": true,
	"readlink": true, "realpath": true, "source": true, ".": true,
}

// commandWrappers run the command that follows them.
var commandWrappers = map[string]bool{
	"sudo": true, "env": true, "time": true, "nohup": true, "command": true,
	"exec": true, "xargs": true, "builtin": true,
}

// shellUnreadable reports why a command's paths cannot be read from its text,
// or "" when they can: the shell would rewrite its words after this check.
//
// Quote-aware, because `awk '{print $1}' f` expands nothing. Inside single
// quotes everything is literal; inside double quotes $ and a backtick still
// expand and a glob does not.
func shellUnreadable(command string) string {
	var quote rune
	escaped := false
	for _, r := range command {
		switch {
		case escaped:
			escaped = false
		case r == '\\' && quote != '\'':
			escaped = true
		case quote == '\'':
			if r == '\'' {
				quote = 0
			}
		case r == '$' || r == '`':
			return "uses a variable or command substitution"
		case quote == '"':
			if r == '"' {
				quote = 0
			}
		case r == '\'' || r == '"':
			quote = r
		case strings.ContainsRune("*?[{", r):
			return "uses a glob or brace expansion"
		}
	}
	return ""
}

// shellOperands returns the words of a command that name a file without
// looking like a path: every non-flag argument of a fileCommands command, and
// every redirection target. `cat notes`, `cd build`, `echo x > out`.
//
// A number is skipped (`head -n 5 f`); a file named only in digits is the
// price. A bare `cd` yields "~", since that is where it goes.
func shellOperands(command string) []string {
	var ids []string
	segments := strings.FieldsFunc(normalizeCommand(command), func(r rune) bool {
		return strings.ContainsRune(";|&\n\r()", r)
	})
	for _, segment := range segments {
		words := strings.Fields(strings.NewReplacer("<", " < ", ">", " > ").Replace(segment))
		name, operands, redirect := "", 0, false
		for _, w := range words {
			switch {
			case w == "<" || w == ">":
				redirect = true
			case redirect:
				redirect = false
				ids = append(ids, w)
			case name == "":
				// Leading VAR=value words and wrappers are not the command.
				if base := strings.ToLower(path.Base(w)); !strings.Contains(w, "=") && !commandWrappers[base] {
					name = base
				}
			case !fileCommands[name]:
			case w == "-" || !strings.HasPrefix(w, "-"):
				operands++
				if strings.Trim(w, "0123456789") != "" {
					ids = append(ids, w)
				}
			}
		}
		if (name == "cd" || name == "pushd") && operands == 0 {
			ids = append(ids, "~")
		}
	}
	return ids
}
