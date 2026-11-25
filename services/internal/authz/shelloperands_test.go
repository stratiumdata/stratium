package authz

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stratiumdata/stratium/pkg/models"
)

func TestShellUnreadable(t *testing.T) {
	for command, unreadable := range map[string]bool{
		"cat /workspace/a.txt":                false,
		"awk '{print $1}' /workspace/a.txt":   false, // single quotes: literal
		`grep "a*b" /workspace/a.txt`:         false, // a quoted glob is not expanded
		`echo \$HOME`:                         false,
		"cat $HOME/notes":                     true,
		`cat "$HOME/notes"`:                   true, // double quotes still expand
		"cat $(echo /etc/shadow)":             true,
		"cat `echo /etc/shadow`":              true,
		"cat /workspace/*.txt":                true,
		"cat /workspace/{a,b}":                true,
		"cat /workspace/a?.txt":               true,
		"cat /workspace/[ab].txt":             true,
		"cat 'it''s' /workspace/$x":           true,
		"cat /workspace/a.txt; echo ${IFS}rm": true,
	} {
		if got := shellUnreadable(command) != ""; got != unreadable {
			t.Errorf("shellUnreadable(%q) = %q, want unreadable=%v", command, shellUnreadable(command), unreadable)
		}
	}
}

func TestShellOperands(t *testing.T) {
	for command, want := range map[string][]string{
		"cat /workspace/a.txt; cat notes": {"/workspace/a.txt", "notes"},
		"cd build && rm -rf out":          {"build", "out"},
		"cd":                              {"~"},
		"cd -":                            {"-"},
		"sudo cat notes":                  {"notes"},
		"FOO=1 env BAR=2 /bin/cat notes":  {"notes"},
		"echo hi > out":                   {"out"},
		"echo hi >> out 2>&1":             {"out"},
		"cat < input":                     {"input"},
		"head -n 5 /workspace/a.txt":      {"/workspace/a.txt"},
		`"cat" 'notes'`:                   {"notes"},
		"ls | xargs cat":                  nil,
		"git status":                      nil, // not a file command: bare words are not operands
		"grep pattern /workspace/a.txt":   nil,
		"ls -la":                          nil,
		"(cd build; ls)":                  {"build"},
		"tee -a log":                      {"log"},
	} {
		if got := shellOperands(command); !reflect.DeepEqual(got, want) {
			t.Errorf("shellOperands(%q) = %#v, want %#v", command, got, want)
		}
	}
}

// The check end to end: what an id_prefix allows and refuses on a shell tool.
func TestCheckResourceConstraints_ShellCommandUnderIDPrefix(t *testing.T) {
	constraints := map[string]string{models.ResourceIDPrefixKey: "/workspace/"}
	for command, wantReason := range map[string]string{
		"cat /workspace/a.txt":                    "",
		"cat /workspace/a.txt | wc -l":            "",
		"git -C /workspace/repo status":           "",
		"cat /workspace/a.txt; cat notes":         `resource "notes" is outside`,
		"cd build; cat /workspace/a.txt":          `resource "build" is outside`,
		"cat /workspace/a.txt > out":              `resource "out" is outside`,
		"cd; cat /workspace/a.txt":                `resource "~" is outside`,
		"cat /workspace/a.txt $HOME/x":            "cannot be evaluated",
		"cat /workspace/*":                        "cannot be evaluated",
		"cat /workspace/a.txt; cat `echo secret`": "cannot be evaluated",
	} {
		ok, reason := checkResourceConstraints(constraints, nil, ShellResourceIDs(command), command)
		if (wantReason == "") != ok || !strings.Contains(reason, wantReason) {
			t.Errorf("%q: allowed=%v reason=%q, want reason containing %q", command, ok, reason, wantReason)
		}
	}

	// No command, no extra checks: a file tool's own path is judged as before.
	if ok, reason := checkResourceConstraints(constraints, nil, []string{"/workspace/$x*"}, ""); !ok {
		t.Errorf("a non-shell resource id was refused: %s", reason)
	}
}
