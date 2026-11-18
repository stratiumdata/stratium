package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// loadPrincipalAuth fills how the PDP learns who a new session is for.
//
// A root delegation names a principal, and that principal's policy decides
// everything issued under it. Taking the name from the request means taking
// it from the PEP, the party being policed. So by default the PDP requires
// an OIDC token from the operator's identity provider and reads the name
// from it; trusting the request has to be asked for by name.
//
// As with the gRPC transport (tls.go), a PDP with neither refuses to start:
// a silent fallback to "believe the caller" would look identical to a
// correctly configured deployment until someone abused it.
func loadPrincipalAuth(c *Config) error {
	c.PrincipalOIDCIssuer = os.Getenv("STRATIUM_PRINCIPAL_OIDC_ISSUER")
	c.PrincipalOIDCAudience = os.Getenv("STRATIUM_PRINCIPAL_OIDC_AUDIENCE")
	c.PrincipalClaim = os.Getenv("STRATIUM_PRINCIPAL_CLAIM")
	c.PrincipalOIDCTimeout = 5 * time.Second
	if v := os.Getenv("STRATIUM_PRINCIPAL_OIDC_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("STRATIUM_PRINCIPAL_OIDC_TIMEOUT: %w", err)
		}
		if d <= 0 {
			return fmt.Errorf("STRATIUM_PRINCIPAL_OIDC_TIMEOUT must be positive, got %s", d)
		}
		c.PrincipalOIDCTimeout = d
	}
	if v := os.Getenv("STRATIUM_PRINCIPAL_AUTH_INSECURE"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("STRATIUM_PRINCIPAL_AUTH_INSECURE: %w", err)
		}
		c.PrincipalAuthInsecure = b
	}

	set := map[string]string{
		"STRATIUM_PRINCIPAL_OIDC_ISSUER":   c.PrincipalOIDCIssuer,
		"STRATIUM_PRINCIPAL_OIDC_AUDIENCE": c.PrincipalOIDCAudience,
		"STRATIUM_PRINCIPAL_CLAIM":         c.PrincipalClaim,
	}
	var missing []string
	for _, k := range []string{
		"STRATIUM_PRINCIPAL_OIDC_ISSUER", "STRATIUM_PRINCIPAL_OIDC_AUDIENCE", "STRATIUM_PRINCIPAL_CLAIM",
	} {
		if set[k] == "" {
			missing = append(missing, k)
		}
	}
	anySet := len(missing) < len(set)

	switch {
	case c.PrincipalAuthInsecure && anySet:
		return fmt.Errorf("STRATIUM_PRINCIPAL_AUTH_INSECURE=true conflicts with the STRATIUM_PRINCIPAL_OIDC_* settings: choose one")
	case c.PrincipalAuthInsecure:
		return nil
	case len(missing) > 0:
		return fmt.Errorf("missing principal authentication settings: %s "+
			"(or set STRATIUM_PRINCIPAL_AUTH_INSECURE=true to trust the subject a caller sends, for local development only)",
			strings.Join(missing, ", "))
	}
	return nil
}
