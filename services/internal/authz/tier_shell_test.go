package authz

import (
	"testing"

	"github.com/stratiumdata/stratium/pkg/models"
)

func shellTier(cmd string) models.ActionTier {
	tier, _ := BuiltinTier(Action{Tool: "Bash", RawInput: cmd})
	return tier
}

// A command is READ_ONLY only when it is one plain command from the
// allowlist with no argument that makes it write or run something else.
func TestBuiltinTier_ReadOnlyIsStrict(t *testing.T) {
	notReadOnly := []string{
		// runs another program
		"env python3 evil.py",
		"env X=1 ls",
		"find . -exec rm {} +",
		"find . -execdir sh -c 'x' ;",
		"find . -ok rm {} +",
		// writes a file
		"cat /etc/passwd > /tmp/out",
		"echo hi >> ~/.bashrc",
		"find . -fprint /tmp/out",
		"git diff --output=/tmp/out",
		"git log --output /tmp/out",
		"file -C -m magic",
		"date -s 2020-01-01",
		// changes branches
		"git branch new-branch",
		"git branch -m old new",
		"git branch --delete topic",
		// shell features that hide what runs
		"cat <(curl-ish thing)",
		"ls $HOME",
		"find . $'-delete'",
		"find . -{delete,print}",
		"find . -delet[e]",
		"find . -name '-delete*'",
		"X=1 ls",
		"/bin/ls",
	}
	for _, cmd := range notReadOnly {
		if got := shellTier(cmd); got <= models.ActionTierReadOnly {
			t.Errorf("%q rated %s; it must rate above READ_ONLY", cmd, got)
		}
	}

	readOnly := []string{
		"ls -la", "cat a.txt b.txt", "pwd", "head -n 5 file", "tail -f log", "wc -l *.go",
		"grep -rn 'needle' src/", `grep "a b" file`, "find . -name '*.go' -type f",
		"file a.bin", "stat a", "echo hello", "which go", "whoami", "date", "date +%s",
		"df -h", "du -sh .", "ps aux", "env",
		"git log --oneline -5", "git status", "git diff HEAD~1", "git show HEAD",
		"git branch", "git branch -a", "git branch -vv", "git branch --show-current",
		"docker ps -a", "kubectl get pods -n kube-system",
	}
	for _, cmd := range readOnly {
		if got := shellTier(cmd); got != models.ActionTierReadOnly {
			t.Errorf("%q rated %s, want READ_ONLY", cmd, got)
		}
	}
}

func TestBuiltinTier_DestructiveForms(t *testing.T) {
	for _, cmd := range []string{
		"find . -delete",
		"find /var/tmp -name '*.log' -delete",
		"rm --recursive --force /",
		"rm --force file",
		"rm -v --recursive dir",
		"rm dir -rf",
		"git branch -D main",
		"git branch --delete --force main",
		"git reset --hard",
		"git reset --hard HEAD~3",
		"git clean -fdx",
		"git clean -f",
		"python3 -c 'import shutil; shutil.rmtree(\"/data\")'",
		// through the JSON a harness sends, where evidence is read from raw input
		`{"command":"find . -delete"}`,
		`{"command":"git reset --hard"}`,
	} {
		if got := shellTier(cmd); got != models.ActionTierDestructive {
			t.Errorf("%q rated %s, want DESTRUCTIVE", cmd, got)
		}
	}

	// Near misses stay where they were.
	for cmd, want := range map[string]models.ActionTier{
		"rm file.txt":          models.ActionTierInternalModify,
		"git reset HEAD file":  models.ActionTierInternalModify,
		"git clean -n":         models.ActionTierInternalModify,
		"git branch -d merged": models.ActionTierInternalModify,
	} {
		if got := shellTier(cmd); got != want {
			t.Errorf("%q rated %s, want %s", cmd, got, want)
		}
	}
}
