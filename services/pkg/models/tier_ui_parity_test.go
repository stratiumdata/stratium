package models_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stratiumdata/stratium/pkg/models"
)

// The admin console renders these tier names. It cannot import Go, so
// clients/ui/src/display.ts holds its own copy of both vocabularies and its
// own doc comment saying it mirrors AgentTrustTier.String() and
// ActionTier.String(). Nothing enforced that, and it drifted: TRUST_TIERS[3]
// read "PRIVILEGED" while String() has always returned "PLATFORM_TRUSTED".
//
// It survived because the UI had a test of its own asserting the wrong name,
// and because the console only ever DISPLAYED the value -- until the field
// became a dropdown and the mislabel turned into something an operator picks.
//
// This is the only place the two languages can be compared, so it lives here
// rather than in the UI suite: Go can read the TypeScript, not the reverse.
const displayTS = "../../../clients/ui/src/display.ts"

func uiTierNames(t *testing.T, constName string) []string {
	t.Helper()

	path := filepath.Clean(displayTS)
	src, err := os.ReadFile(path)
	if err != nil {
		// A moved or renamed display.ts must fail loudly here. Skipping would
		// silently retire the only check that these two lists agree.
		t.Fatalf("read %s: %v -- if the admin UI moved, update displayTS", path, err)
	}

	re := regexp.MustCompile(`export const ` + constName + ` = \[([^\]]*)\]`)
	m := re.FindSubmatch(src)
	if m == nil {
		t.Fatalf("%s: no `export const %s = [...]` found", path, constName)
	}

	var names []string
	for _, raw := range strings.Split(string(m[1]), ",") {
		if s := strings.Trim(strings.TrimSpace(raw), "'\""); s != "" {
			names = append(names, s)
		}
	}
	return names
}

func TestActionTierNamesMatchTheAdminUI(t *testing.T) {
	ui := uiTierNames(t, "ACTION_TIERS")

	var want []string
	for tier := models.ActionTierReasoning; tier <= models.ActionTierDestructive; tier++ {
		want = append(want, tier.String())
	}

	assertSameNames(t, "ACTION_TIERS", want, ui)
}

func TestTrustTierNamesMatchTheAdminUI(t *testing.T) {
	ui := uiTierNames(t, "TRUST_TIERS")

	var want []string
	for tier := models.TrustTierUnverified; tier <= models.TrustTierPlatformTrusted; tier++ {
		want = append(want, tier.String())
	}

	assertSameNames(t, "TRUST_TIERS", want, ui)
}

// assertSameNames compares by INDEX, because the index is the wire value: a
// list that merely contains the right names in the wrong order would send the
// wrong tier under the right label, which is worse than a missing name.
func assertSameNames(t *testing.T, constName string, want, got []string) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("%s has %d names %v, Go has %d %v", constName, len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s[%d] = %q, Go's String() = %q -- %s", constName, i, got[i], want[i],
				fmt.Sprintf("the console would show %q for a tier the rest of the system calls %q", got[i], want[i]))
		}
	}
}
