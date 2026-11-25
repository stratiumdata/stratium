package authz

import (
	"path"
	"strings"
	"unicode"
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

// commandWrappers are words the real command can follow: programs that run
// another command, and the shell's own reserved words.
var commandWrappers = map[string]bool{
	"sudo": true, "env": true, "time": true, "nohup": true, "command": true,
	"exec": true, "xargs": true, "builtin": true, "nice": true, "timeout": true,
	"if": true, "then": true, "else": true, "elif": true, "do": true,
	"while": true, "until": true, "!": true,
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

// Marks shellSegments puts in a segment where a redirection stood. A word can
// never equal one: no word holds a NUL.
const (
	redirectFile = "\x00>"  // the next word is a file
	redirectDup  = "\x00>&" // the next word is a file, or a descriptor (2>&1)
)

// shellSegments splits a command into its simple commands, each a list of
// words with quotes and backslashes removed.
//
// Split first, unquote second, the order a shell uses. Only an unquoted,
// unescaped ; | & ( ) or newline ends a command, so `cat "a;" notes` is one
// command with two arguments and not a command named notes.
func shellSegments(command string) [][]string {
	var (
		segments [][]string
		words    []string
		word     strings.Builder
		inWord   bool
		quote    rune
		escaped  bool
	)
	endWord := func() {
		if inWord {
			words = append(words, word.String())
			word.Reset()
			inWord = false
		}
	}
	endSegment := func() {
		endWord()
		if len(words) > 0 {
			segments = append(segments, words)
			words = nil
		}
	}
	runes := []rune(command)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		switch {
		case escaped:
			escaped = false
			if r != '\n' { // backslash-newline joins two lines
				word.WriteRune(r)
				inWord = true
			}
		case r == '\\' && quote != '\'':
			escaped = true
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				word.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote, inWord = r, true
		case r == '<' || r == '>' || (r == '&' && i+1 < len(runes) && runes[i+1] == '>'):
			// A redirection in any spelling: > >> >| >& &> &>> < << <>.
			// Digits directly before it are a descriptor, not a word.
			if inWord && strings.Trim(word.String(), "0123456789") == "" {
				word.Reset()
				inWord = false
			}
			endWord()
			mark := redirectFile
			for ; i+1 < len(runes) && strings.ContainsRune("<>|&", runes[i+1]); i++ {
				if runes[i+1] == '&' {
					mark = redirectDup
				}
			}
			words = append(words, mark)
		case strings.ContainsRune(";|&()\n\r", r):
			endSegment()
		case unicode.IsSpace(r):
			endWord()
		default:
			word.WriteRune(r)
			inWord = true
		}
	}
	endSegment()
	return segments
}

// shellOperands returns the words of a command that name a file without
// looking like a path: every non-flag argument of a fileCommands command, and
// every redirection target. `cat notes`, `cd build`, `echo x > out`.
//
// The command of a segment is its first word that is not an assignment, a
// flag or a wrapper. After a wrapper the search goes on past words it cannot
// place (`sudo -u root cat notes`), so a file command anywhere behind one
// still counts.
//
// A number is skipped (`head -n 5 f`); a file named only in digits is the
// price. A bare `cd` yields "~", since that is where it goes.
func shellOperands(command string) []string {
	var ids []string
	for _, words := range shellSegments(command) {
		name, searching, wrapped, operands, redirect := "", true, false, 0, ""
		for _, w := range words {
			base := strings.ToLower(path.Base(w))
			switch {
			case w == redirectFile || w == redirectDup:
				redirect = w
			case redirect != "":
				if redirect == redirectFile || strings.Trim(w, "0123456789-") != "" {
					ids = append(ids, w)
				}
				redirect = ""
			case w == "":
			case searching && (strings.Contains(w, "=") || strings.HasPrefix(w, "-")):
			case searching && commandWrappers[base]:
				wrapped = true
			case searching && fileCommands[base]:
				name, searching = base, false
			case searching:
				searching = wrapped
			case name == "":
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
