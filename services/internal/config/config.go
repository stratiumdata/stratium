// Package config loads the PDP's configuration from the environment.
//
// Required values have no defaults. A PDP that starts with a guessed database
// URL or a guessed tenant is worse than one that refuses to start.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	DatabaseURL string        // STRATIUM_DATABASE_URL (required)
	TenantID    string        // STRATIUM_TENANT_ID (required)
	ListenAddr  string        // STRATIUM_LISTEN_ADDR, default ":50051"
	MaxDepth    int           // STRATIUM_MAX_DELEGATION_DEPTH, default 5
	DBTimeout   time.Duration // STRATIUM_DB_TIMEOUT, default 5s
}

func Load() (Config, error) {
	c := Config{
		ListenAddr: envOr("STRATIUM_LISTEN_ADDR", ":50051"),
		MaxDepth:   5,
		DBTimeout:  5 * time.Second,
	}
	var err error

	if c.DatabaseURL = os.Getenv("STRATIUM_DATABASE_URL"); c.DatabaseURL == "" {
		return c, fmt.Errorf("STRATIUM_DATABASE_URL is required")
	}
	// The tenant is configuration, never request input. See the plan's global
	// constraints: the predecessor trusted a client-supplied header and that
	// was a critical authentication bypass.
	if c.TenantID = os.Getenv("STRATIUM_TENANT_ID"); c.TenantID == "" {
		return c, fmt.Errorf("STRATIUM_TENANT_ID is required")
	}
	if v := os.Getenv("STRATIUM_MAX_DELEGATION_DEPTH"); v != "" {
		if c.MaxDepth, err = strconv.Atoi(v); err != nil {
			return c, fmt.Errorf("STRATIUM_MAX_DELEGATION_DEPTH: %w", err)
		}
	}
	if c.MaxDepth < 1 {
		return c, fmt.Errorf("STRATIUM_MAX_DELEGATION_DEPTH must be at least 1, got %d", c.MaxDepth)
	}
	if v := os.Getenv("STRATIUM_DB_TIMEOUT"); v != "" {
		if c.DBTimeout, err = time.ParseDuration(v); err != nil {
			return c, fmt.Errorf("STRATIUM_DB_TIMEOUT: %w", err)
		}
	}
	return c, nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
