// Package config loads the PDP's configuration from the environment.
//
// Required values have no defaults. A PDP that starts with a guessed database
// URL or a guessed tenant is worse than one that refuses to start.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	DatabaseURL string // STRATIUM_DATABASE_URL (required) — the serving connection.
	// MigrationDatabaseURL (optional) is used only to apply migrations, on a
	// connection closed before serving begins — see cmd/stratium-pdp/main.go.
	// Left empty, the PDP skips migrations and assumes an already-migrated
	// schema, logging that assumption plainly rather than guessing.
	MigrationDatabaseURL string        // STRATIUM_MIGRATION_DATABASE_URL (optional)
	TenantID             string        // STRATIUM_TENANT_ID (required)
	ListenAddr           string        // STRATIUM_LISTEN_ADDR, default ":50051"
	MaxDepth             int           // STRATIUM_MAX_DELEGATION_DEPTH, default 5
	DBTimeout            time.Duration // STRATIUM_DB_TIMEOUT, default 5s

	// TokenSigningKeyPath is the filesystem path to a PEM-encoded EC private
	// key: the PDP's current delegation-token signing key, which also
	// verifies (STRATIUM_TOKEN_SIGNING_KEY_PATH, required). Spec §4.7.1 K1:
	// the environment holds the path, never the key material, so a leaked
	// environment dump or crash report never leaks a signing key — only
	// internal/token.Load ever reads the file this names.
	TokenSigningKeyPath string
	// TokenPreviousKeyPath is the filesystem path to a PEM-encoded EC key
	// retained for verification only (STRATIUM_TOKEN_PREVIOUS_KEY_PATH,
	// optional). Left empty, no previous key is loaded — the steady-state
	// case outside a rotation window. Set it to the outgoing current key
	// during rotation so a token issued moments before the restart that
	// swaps STRATIUM_TOKEN_SIGNING_KEY_PATH still verifies; see
	// internal/token's own package doc for why a previous key can verify but
	// is structurally unable to sign.
	TokenPreviousKeyPath string

	// ApprovalTTL is how long a freshly created pending approval remains
	// valid before Approval.Verify's expiry check rejects it — the value
	// CreateApproval's expires_at is computed from. Configurable, default
	// 24h, the same "operational tunable with a sensible default" treatment
	// MaxDepth/DBTimeout already get above: how long an organization can
	// reasonably expect a human to respond to an escalation varies by
	// deployment, unlike DatabaseURL/TenantID, where guessing is unsafe at
	// any value.
	ApprovalTTL time.Duration // STRATIUM_APPROVAL_TTL, default 24h

	// PolicyLanguages is the deployment's enabled set of policy engines —
	// STRATIUM_POLICY_LANGUAGES, a comma-separated list, default every
	// language this build ships (defaultPolicyLanguages below). Unlike
	// DatabaseURL/TenantID above, this has a default: an operator who
	// enables nothing unusual gets every engine for free, the same way
	// leaving STRATIUM_LISTEN_ADDR unset gets ":50051" rather than an error.
	//
	// This package only parses the list; it does not know which names are
	// real. Deliberately: recognizing a name requires an actual engine
	// constructor (cedar.New, rego.New, ...), and this package has no
	// dependency on internal/policy or its engines to name a default with —
	// gaining one just to validate four string literals would be exactly
	// the kind of coupling a "loads config from the environment" package
	// should not need. cmd/stratium-pdp's own buildRegistry (registry.go)
	// is where a name with no matching engine becomes the startup failure
	// the brief asks for: the same fail-fast principle this package applies
	// to DatabaseURL/TenantID, just enforced one step later, by the code
	// that actually owns the answer to "is this a real language."
	PolicyLanguages []string
}

// defaultPolicyLanguages is every policy engine this binary ships today,
// used when STRATIUM_POLICY_LANGUAGES is unset. Plain string literals, not
// each engine's own Language() — see the Config.PolicyLanguages doc comment
// above for why this package does not import them.
var defaultPolicyLanguages = []string{"cedar", "json", "rego", "xacml"}

func Load() (Config, error) {
	c := Config{
		ListenAddr:      envOr("STRATIUM_LISTEN_ADDR", ":50051"),
		MaxDepth:        5,
		DBTimeout:       5 * time.Second,
		ApprovalTTL:     24 * time.Hour,
		PolicyLanguages: defaultPolicyLanguages,
	}
	var err error

	// Every required-with-no-default value is checked before any of them can
	// return: a deployment missing both STRATIUM_DATABASE_URL and
	// STRATIUM_TENANT_ID (say, a fresh environment with none of the PDP's
	// variables set yet) learns both gaps from one run, not one restart per
	// gap. This is the same "collect every missing variable" idiom
	// cmd/stratium-pep/config.go's requiredEnv already uses for the PEP's own
	// required set — applied here so the PDP's required config behaves the
	// same way, not a different, weaker one.
	var missing []string
	c.DatabaseURL = os.Getenv("STRATIUM_DATABASE_URL")
	if c.DatabaseURL == "" {
		missing = append(missing, "STRATIUM_DATABASE_URL")
	}
	// The tenant is configuration, never request input. See the plan's global
	// constraints: the predecessor trusted a client-supplied header and that
	// was a critical authentication bypass.
	c.TenantID = os.Getenv("STRATIUM_TENANT_ID")
	if c.TenantID == "" {
		missing = append(missing, "STRATIUM_TENANT_ID")
	}
	// Presence only, matching DatabaseURL/TenantID's own treatment at this
	// layer: this package validates that a value was configured, not that the
	// file at the path is readable or holds a real EC key — that check needs
	// the filesystem and crypto/ecdsa, which belong to internal/token.Load,
	// same layering registry.go's own buildRegistry already uses for
	// STRATIUM_POLICY_LANGUAGES (syntax here, semantics one level up).
	c.TokenSigningKeyPath = os.Getenv("STRATIUM_TOKEN_SIGNING_KEY_PATH")
	if c.TokenSigningKeyPath == "" {
		missing = append(missing, "STRATIUM_TOKEN_SIGNING_KEY_PATH")
	}
	if len(missing) > 0 {
		return c, fmt.Errorf("missing required configuration: %s", strings.Join(missing, ", "))
	}

	// No presence check: unset is a valid, deliberate choice (skip migrations),
	// not a missing required value.
	c.MigrationDatabaseURL = os.Getenv("STRATIUM_MIGRATION_DATABASE_URL")
	// No presence check, for the same reason: unset means no previous key is
	// loaded, a deliberate and common choice outside a rotation window, not a
	// missing required value.
	c.TokenPreviousKeyPath = os.Getenv("STRATIUM_TOKEN_PREVIOUS_KEY_PATH")
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
	if v := os.Getenv("STRATIUM_APPROVAL_TTL"); v != "" {
		if c.ApprovalTTL, err = time.ParseDuration(v); err != nil {
			return c, fmt.Errorf("STRATIUM_APPROVAL_TTL: %w", err)
		}
	}
	if c.ApprovalTTL <= 0 {
		// Fail fast rather than mint an approval that is already expired the
		// instant it is created (Approval.Verify's expiry check is strict:
		// now must be BEFORE expires_at) — a misconfiguration an operator
		// would otherwise only discover as every single escalation retry
		// mysteriously denying "expired."
		return c, fmt.Errorf("STRATIUM_APPROVAL_TTL must be positive, got %s", c.ApprovalTTL)
	}
	if v := os.Getenv("STRATIUM_POLICY_LANGUAGES"); v != "" {
		if c.PolicyLanguages, err = splitPolicyLanguages(v); err != nil {
			return c, err
		}
	}
	return c, nil
}

// splitPolicyLanguages splits a comma-separated STRATIUM_POLICY_LANGUAGES
// value into its entries, trimming surrounding whitespace so
// "cedar, rego" reads the same as "cedar,rego". An empty entry — a leading,
// trailing, or doubled comma — is rejected rather than silently dropped:
// this package cannot tell "typo" from "meant to write something here"
// apart, and dropping it silently would let a config with a stray comma
// deploy with fewer engines than its author believed they listed.
func splitPolicyLanguages(v string) ([]string, error) {
	parts := strings.Split(v, ",")
	langs := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, fmt.Errorf("STRATIUM_POLICY_LANGUAGES: empty language name in %q (check for a stray comma)", v)
		}
		langs = append(langs, p)
	}
	return langs, nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
