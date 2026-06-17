// go/internal/catalog/classifier_test.go
package catalog

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClassifierResolve(t *testing.T) {
	repos := map[string]Classification{
		"acme/secret-repo": {Classification: "CONFIDENTIAL", Hierarchy: "commercial"},
	}
	def := &Classification{Classification: "INTERNAL", Hierarchy: "commercial"}

	t.Run("known repo returns mapped classification", func(t *testing.T) {
		c := NewClassifier(repos, def)
		got, err := c.Resolve("acme/secret-repo")
		require.NoError(t, err)
		assert.Equal(t, "CONFIDENTIAL", got.Classification)
		assert.Equal(t, "commercial", got.Hierarchy)
	})

	t.Run("unknown repo falls back to default", func(t *testing.T) {
		c := NewClassifier(repos, def)
		got, err := c.Resolve("acme/other-repo")
		require.NoError(t, err)
		assert.Equal(t, "INTERNAL", got.Classification)
	})

	t.Run("unknown repo with no default fails closed", func(t *testing.T) {
		c := NewClassifier(repos, nil)
		_, err := c.Resolve("acme/other-repo")
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrUnclassified))
	})
}
