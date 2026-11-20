package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pep.env")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestApplyConfigFile_FileReplacesEnvironment(t *testing.T) {
	t.Setenv("STRATIUM_PEP_PDP_ADDR", "from-env:1")
	t.Setenv("STRATIUM_PEP_PDP_INSECURE", "true")
	t.Setenv("HOME_GROWN", "untouched")
	path := writeConfig(t, "# pinned\n\nSTRATIUM_PEP_PDP_ADDR = pinned:50051\nSTRATIUM_PEP_PURPOSE=a=b\n")

	for _, args := range [][]string{{"--config", path}, {"--config=" + path}} {
		t.Setenv("STRATIUM_PEP_PDP_ADDR", "from-env:1")
		if err := applyConfigFile(args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if got := os.Getenv("STRATIUM_PEP_PDP_ADDR"); got != "pinned:50051" {
			t.Errorf("%v: PDP_ADDR = %q, want the file's value", args, got)
		}
	}
	if got := os.Getenv("STRATIUM_PEP_PURPOSE"); got != "a=b" {
		t.Errorf("PURPOSE = %q, want everything after the first =", got)
	}
	if got, set := os.LookupEnv("STRATIUM_PEP_PDP_INSECURE"); set {
		t.Errorf("PDP_INSECURE = %q, a setting the file leaves out must not come from the environment", got)
	}
	if got := os.Getenv("HOME_GROWN"); got != "untouched" {
		t.Errorf("HOME_GROWN = %q, only STRATIUM_PEP_* variables are cleared", got)
	}
}

func TestApplyConfigFile_NoFlagChangesNothing(t *testing.T) {
	t.Setenv("STRATIUM_PEP_PDP_ADDR", "from-env:1")
	if err := applyConfigFile(nil); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("STRATIUM_PEP_PDP_ADDR"); got != "from-env:1" {
		t.Errorf("PDP_ADDR = %q", got)
	}
}

func TestApplyConfigFile_Errors(t *testing.T) {
	cases := map[string][]string{
		"missing file":   {"--config", filepath.Join(t.TempDir(), "absent")},
		"no path":        {"--config"},
		"empty path":     {"--config="},
		"not KEY=value":  {"--config", writeConfig(t, "STRATIUM_PEP_PDP_ADDR\n")},
		"foreign prefix": {"--config", writeConfig(t, "PATH=/tmp\n")},
	}
	for name, args := range cases {
		if err := applyConfigFile(args); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

// A hook that cannot read its pinned configuration must answer deny on
// stdout: falling back to the environment would hand the choice of PDP back
// to whoever controls the environment.
func TestDispatch_Hook_UnreadableConfigDenies(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := dispatch([]string{"hook", "--config", filepath.Join(t.TempDir(), "absent")},
		strings.NewReader("{}"), &stdout, &stderr)
	if code != 2 || !strings.Contains(stdout.String(), `"permissionDecision":"deny"`) {
		t.Fatalf("code=%d stdout=%s", code, stdout.String())
	}
}

func TestDispatch_SessionStart_UnreadableConfigFails(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := dispatch([]string{"session-start", "--config"}, strings.NewReader(""), &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "--config") {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
}
