// go/internal/catalog/config_test.go
package catalog

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.json")
	require.NoError(t, os.WriteFile(path, []byte(`{
      "enabled": true,
      "providers": ["github"],
      "github": {
        "repo_classifications": {
          "acme/secret-repo": {"classification": "CONFIDENTIAL", "hierarchy": "commercial"}
        },
        "default_classification": {"classification": "INTERNAL", "hierarchy": "commercial"}
      }
    }`), 0600))

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.True(t, cfg.Enabled)
	assert.Equal(t, "github", cfg.GitHub.BrokerAlias)             // default applied
	assert.Equal(t, "https://api.github.com", cfg.GitHub.BaseURL) // default applied

	c := cfg.Classifier()
	got, err := c.Resolve("acme/secret-repo")
	require.NoError(t, err)
	assert.Equal(t, "CONFIDENTIAL", got.Classification)
}

func TestLoadConfigMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	require.Error(t, err)
}
