// go/internal/catalog/config.go
package catalog

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config is the opt-in SaaS catalog configuration, loaded from a JSON file
// (default off). Path comes from the -catalog-config flag / STRATIUM_CATALOG_CONFIG.
type Config struct {
	// Enabled controls whether the catalog is active; callers MUST check Enabled before using the catalog.
	Enabled   bool         `json:"enabled"`
	Providers []string     `json:"providers"`
	GitHub    GitHubConfig `json:"github"`
}

// GitHubConfig configures the GitHub catalog provider.
// Note: in v1 the Keycloak IdP alias and the resource "provider" name are fixed to "github".
type GitHubConfig struct {
	BaseURL               string                    `json:"base_url"`
	DefaultClassification *Classification           `json:"default_classification"`
	RepoClassifications   map[string]Classification `json:"repo_classifications"`
}

// Load reads and validates the catalog config file, applying defaults.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-supplied config path (CLI flag), not untrusted input
	if err != nil {
		return nil, fmt.Errorf("read catalog config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse catalog config: %w", err)
	}
	if cfg.GitHub.BaseURL == "" {
		cfg.GitHub.BaseURL = "https://api.github.com"
	}
	return &cfg, nil
}

// Classifier builds a Classifier from the GitHub repo map + default.
func (c *Config) Classifier() *Classifier {
	return NewClassifier(c.GitHub.RepoClassifications, c.GitHub.DefaultClassification)
}
