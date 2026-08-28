package authz

import (
	"reflect"
	"testing"
)

func TestShellResourceIDs(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    []string
	}{
		{"a single absolute path", "cat /tmp/notes.txt", []string{"/tmp/notes.txt"}},
		{
			// THE case this function exists for. Extracting only the first
			// path would label this UNCLASSIFIED under a catch-all while the
			// command still reads the secret -- R4's "lying does not pay"
			// broken, and a loud denial turned into a silent allow.
			"every path in a compound command, not just the first",
			"cat /tmp/notes.txt; cat /secret/plans.txt",
			[]string{"/tmp/notes.txt", "/secret/plans.txt"},
		},
		{"across a pipe", "cat /secret/a.txt | grep -i x", []string{"/secret/a.txt"}},
		{"across &&", "mkdir /tmp/x && cp /secret/y /tmp/x", []string{"/tmp/x", "/secret/y"}},
		{"a redirect target", "echo hi > /secret/out.txt", []string{"/secret/out.txt"}},
		{"the right-hand side of a flag", "rg --file=/secret/patterns x", []string{"/secret/patterns"}},
		{"a home-relative path", "cat ~/notes.txt", []string{"~/notes.txt"}},
		{"a relative path with an extension", "cat notes.txt", []string{"notes.txt"}},
		{"a dot-relative path", "cat ./config.yaml", []string{"./config.yaml"}},

		// Quoting and word-splitting tricks are normalized the same way the
		// tier classifier normalizes them, and for the same reason: an
		// adversary must not be able to hide a path from the extractor by
		// spelling it differently than the shell reads it.
		{"quoted", `cat "/secret/plans.txt"`, []string{"/secret/plans.txt"}},
		{"single-quoted", `cat '/secret/plans.txt'`, []string{"/secret/plans.txt"}},
		{"IFS-split", "cat${IFS}/secret/plans.txt", []string{"/secret/plans.txt"}},
		{"inside a substitution", "cat $(ls /secret/dir)", []string{"/secret/dir"}},

		// Over-extraction is inert and under-extraction is dangerous, so the
		// bias is toward inclusion -- but a token with no path shape at all
		// contributes nothing, or every flag would become a resource.
		{"no paths at all", "npm test", nil},
		{"flags are not paths", "ls -la", nil},
		{"a bare command", "whoami", nil},

		{"deduplicated, in source order", "cp /a/b.txt /a/b.txt", []string{"/a/b.txt"}},
		{"empty", "", nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ShellResourceIDs(tc.command)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ShellResourceIDs(%q) = %#v, want %#v", tc.command, got, tc.want)
			}
		})
	}
}

// TestShellResourceIDs_FindsEveryPathAnAttackerMustStillName is the property
// the whole design rests on, stated as a property rather than a table row:
// a decoy prepended to a command cannot remove the real target, because the
// command needs the real target to do anything. So the extractor's output
// must always CONTAIN the dangerous path, whatever is put in front of it.
func TestShellResourceIDs_FindsEveryPathAnAttackerMustStillName(t *testing.T) {
	const target = "/secret/plans.txt"
	decoys := []string{
		"cat /tmp/ok.txt; cat " + target,
		"cat /tmp/ok.txt && cat " + target,
		"cat /tmp/ok.txt | tee " + target,
		"echo /tmp/ok.txt; cat " + target + " # /tmp/ok.txt",
		`cat "/tmp/ok.txt"; cat "` + target + `"`,
	}

	for _, command := range decoys {
		t.Run(command, func(t *testing.T) {
			got := ShellResourceIDs(command)
			found := false
			for _, id := range got {
				if id == target {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("ShellResourceIDs(%q) = %#v, which does not contain %q. A decoy just hid "+
					"the real target -- this is the R4 failure the design exists to prevent",
					command, got, target)
			}
		})
	}
}
