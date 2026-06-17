// go/internal/catalog/tier_test.go
package catalog

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAssessTier(t *testing.T) {
	cases := map[string]int{
		"read": 1, "search": 1, "list": 1,
		"create": 2, "update": 2,
		"send": 3, "publish": 3,
		"delete": 4, "execute": 4,
		"think": 0, "": 0,
	}
	for action, want := range cases {
		assert.Equalf(t, want, AssessTier(action), "AssessTier(%q)", action)
	}
}

func TestGuardTier(t *testing.T) {
	t.Run("declared equals assessed passes", func(t *testing.T) {
		require.NoError(t, GuardTier("delete", 4))
	})
	t.Run("declared above assessed passes", func(t *testing.T) {
		require.NoError(t, GuardTier("read", 2))
	})
	t.Run("declared below assessed fails (anti-spoofing)", func(t *testing.T) {
		require.Error(t, GuardTier("delete", 1))
	})
	t.Run("unknown action is rejected", func(t *testing.T) {
		require.Error(t, GuardTier("frobnicate", 0))
	})
}
