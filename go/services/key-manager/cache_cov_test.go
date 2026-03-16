//go:build !fips

package key_manager

import "testing"

func TestCoverageFinal80_CloneKeyNil(t *testing.T) {
	if got := cloneKey(nil); got != nil {
		t.Fatal("expected nil")
	}
}
