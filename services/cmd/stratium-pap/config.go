// config.go loads stratium-pap's configuration from the environment. Every
// value with no safe guess -- the tenant, the IdP to trust, what to accept
// as this deployment's audience, which claim carries a role, and which
// claim values mean what -- is required with no default, the same
// "guessing is unsafe" rule internal/config.Load applies to
// STRATIUM_DATABASE_URL and STRATIUM_TENANT_ID for the PDP. A single
// missing []string accumulates every gap before Load returns, so an
// operator sees every missing key from one run rather than fixing one and
// restarting to discover the next -- see loadConfig's own doc comment for
// why this is ONE loader rather than several, which is what makes that
// property automatic here instead of something a combineConfigErrors-style
// helper has to restore after the fact (cmd/stratium-pep's mcp/hook config
// split needed exactly that fix once mcpConfig started composing a second,
// independently loaded config).
//
// What is NOT required-with-no-default: ListenAddr and OIDCTimeout are
// operational tunables with a sensible default, like the PDP's own
// ListenAddr/DBTimeout -- unlike the tenant or the IdP, there is no unsafe
// guess to make by leaving them unset.
//
// This package only checks presence and syntax (a group list splits
// cleanly, a duplicate group name is rejected, a timeout parses and is
// positive). It does not contact the IdP: discovering whether
// STRATIUM_PAP_OIDC_ISSUER actually names a reachable OIDC provider is
// semantic validation belonging to NewVerifier (oidc.go), called
// separately from main's run -- the same syntax-here/semantics-one-level-up
// split internal/config.Config's own doc comment describes for
// STRATIUM_POLICY_LANGUAGES versus cmd/stratium-pdp's buildRegistry.
package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Config is stratium-pap's startup configuration. TenantID is the whole of
// N1's "tenant is startup configuration and appears in no request": it is
// read here, once, and nowhere in this binary is there a second path by
// which a tenant could be named -- see the package doc on server.go for how
// that is kept true once routes exist.
type Config struct {
	TenantID string // STRATIUM_PAP_TENANT_ID (required)

	OIDCIssuer   string        // STRATIUM_PAP_OIDC_ISSUER (required)
	OIDCAudience string        // STRATIUM_PAP_OIDC_AUDIENCE (required)
	OIDCTimeout  time.Duration // STRATIUM_PAP_OIDC_TIMEOUT, default 5s

	// RoleClaim names the single OIDC claim resolveRole reads (N2). Not
	// defaulted to a guess like "roles" or "groups": a wrong guess would
	// not fail loudly, it would just refuse every operator, since their
	// IdP's actual claim would then never be consulted -- indistinguishable
	// from a working deployment nobody has been granted a role on yet.
	RoleClaim string // STRATIUM_PAP_ROLE_CLAIM (required)

	// ApproverClaim names the OIDC claim role.go's resolveApproverIdentity
	// reads to satisfy N7/N8 (spec §4.10.1) -- a second, independently
	// configured claim from RoleClaim above, since it answers a different
	// question ("is this operator the chain's root principal," never "what
	// may this operator do"). No default, the same "a wrong guess fails
	// silently, not loudly" reasoning RoleClaim's own comment gives:
	// approvals.root_principal is populated from a PEP's own
	// DecideRequest.Subject configuration (an email, in practice), and
	// guessing the wrong claim name here would not error, it would just
	// make every approval attempt fail N7's comparison, indistinguishable
	// from an operator who genuinely is not the root principal.
	ApproverClaim string // STRATIUM_PAP_APPROVER_CLAIM (required)

	// Roles maps a customer's own claim values (group names, typically) to
	// the three fixed roles -- see newRoleMapping (role.go) for how the
	// three *_GROUPS variables below combine into this and why a value
	// listed under two roles fails startup instead of picking one.
	Roles RoleMapping // STRATIUM_PAP_{ADMIN,EDITOR,VIEWER}_GROUPS (all required)

	// ListenAddr has a default: unlike the values above, there is no unsafe
	// guess here, the same reasoning internal/config.Load applies to the
	// PDP's own ListenAddr. This binary serves plain HTTP; TLS is
	// assumed to terminate upstream (ingress or a reverse proxy), a
	// deployment-topology choice out of scope for this task.
	ListenAddr string // STRATIUM_PAP_LISTEN_ADDR, default ":8080"

	// DatabaseURL is required with no default, the same "guessing is unsafe"
	// treatment TenantID/OIDCIssuer get above and internal/config.Config
	// gives the PDP's own STRATIUM_DATABASE_URL: Task 3 is this binary's
	// first task with any database access at all (server.go's own package
	// doc, written in Task 1, names this exact call as the one this task
	// would add). This process authenticates as stratium_pap_login
	// (migrations/000016_stratium_pap_role) — the write role Task 2 built —
	// never stratium_app; a URL naming the wrong role would fail closed on
	// the first write, not silently reuse the PDP's own read-only grants.
	DatabaseURL string // STRATIUM_PAP_DATABASE_URL (required)

	// DBTimeout has a default, unlike DatabaseURL: an operator who wants a
	// non-default connect timeout can set one, but there is no unsafe value
	// to guess by leaving it unset, the same "operational tunable, not an
	// unsafe guess" reasoning ListenAddr and OIDCTimeout above already carry.
	DBTimeout time.Duration // STRATIUM_PAP_DB_TIMEOUT, default 5s
}

const defaultListenAddr = ":8080"
const defaultOIDCTimeout = 5 * time.Second
const defaultDBTimeout = 5 * time.Second

// loadConfig reads Config from the environment. It is the only config
// loader this binary has -- one Config struct, one function, one missing
// []string -- deliberately, rather than splitting (say) OIDC-related
// fields into a second loader called alongside this one: cmd/stratium-pep's
// mcp mode originally loaded two independently fail-fast configs in
// sequence, and an operator missing values in both discovered the second
// group's gaps only after fixing the first and rerunning (fixed in
// combineConfigErrors, mcp.go). A single loader over a single struct can't
// develop that bug: there is only one missing slice, and every field is
// appended to it before the one check at the bottom.
func loadConfig() (Config, error) {
	var missing []string
	cfg := Config{
		ListenAddr:  defaultListenAddr,
		OIDCTimeout: defaultOIDCTimeout,
		DBTimeout:   defaultDBTimeout,
	}

	cfg.TenantID = requiredEnv("STRATIUM_PAP_TENANT_ID", &missing)
	cfg.OIDCIssuer = requiredEnv("STRATIUM_PAP_OIDC_ISSUER", &missing)
	cfg.OIDCAudience = requiredEnv("STRATIUM_PAP_OIDC_AUDIENCE", &missing)
	cfg.RoleClaim = requiredEnv("STRATIUM_PAP_ROLE_CLAIM", &missing)
	cfg.ApproverClaim = requiredEnv("STRATIUM_PAP_APPROVER_CLAIM", &missing)
	adminGroupsRaw := requiredEnv("STRATIUM_PAP_ADMIN_GROUPS", &missing)
	editorGroupsRaw := requiredEnv("STRATIUM_PAP_EDITOR_GROUPS", &missing)
	viewerGroupsRaw := requiredEnv("STRATIUM_PAP_VIEWER_GROUPS", &missing)
	cfg.DatabaseURL = requiredEnv("STRATIUM_PAP_DATABASE_URL", &missing)

	if len(missing) > 0 {
		return Config{}, missingConfigError(missing)
	}

	adminGroups, err := splitGroups("STRATIUM_PAP_ADMIN_GROUPS", adminGroupsRaw)
	if err != nil {
		return Config{}, err
	}
	editorGroups, err := splitGroups("STRATIUM_PAP_EDITOR_GROUPS", editorGroupsRaw)
	if err != nil {
		return Config{}, err
	}
	viewerGroups, err := splitGroups("STRATIUM_PAP_VIEWER_GROUPS", viewerGroupsRaw)
	if err != nil {
		return Config{}, err
	}
	cfg.Roles, err = newRoleMapping(adminGroups, editorGroups, viewerGroups)
	if err != nil {
		return Config{}, fmt.Errorf("role groups: %w", err)
	}

	if v := os.Getenv("STRATIUM_PAP_LISTEN_ADDR"); v != "" {
		cfg.ListenAddr = v
	}
	if v := os.Getenv("STRATIUM_PAP_OIDC_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("STRATIUM_PAP_OIDC_TIMEOUT: %w", err)
		}
		cfg.OIDCTimeout = d
	}
	if cfg.OIDCTimeout <= 0 {
		// Fail fast rather than let NewVerifier's discovery call use a
		// zero or negative timeout, which context.WithTimeout treats as
		// "already expired" -- every OIDC discovery attempt would fail,
		// and the resulting error would misdescribe a config mistake as an
		// unreachable IdP.
		return Config{}, fmt.Errorf("STRATIUM_PAP_OIDC_TIMEOUT must be positive, got %s", cfg.OIDCTimeout)
	}

	if v := os.Getenv("STRATIUM_PAP_DB_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("STRATIUM_PAP_DB_TIMEOUT: %w", err)
		}
		cfg.DBTimeout = d
	}
	if cfg.DBTimeout <= 0 {
		// Same reasoning as the OIDCTimeout check above, applied to the
		// database connect/ping deadline main.go's run() uses: a zero or
		// negative value makes context.WithTimeout treat the deadline as
		// already expired, misdescribing a config mistake as an unreachable
		// database.
		return Config{}, fmt.Errorf("STRATIUM_PAP_DB_TIMEOUT must be positive, got %s", cfg.DBTimeout)
	}

	return cfg, nil
}

// requiredEnv reads key from the environment, appending key to *missing
// when it is unset or empty. Matches cmd/stratium-pep/config.go's helper of
// the same name exactly (small enough, and tied closely enough to this
// file's own *missing accumulator, that importing across two independent
// "cmd" binaries would trade four lines of duplication for a coupling
// neither binary otherwise has).
func requiredEnv(key string, missing *[]string) string {
	v := os.Getenv(key)
	if v == "" {
		*missing = append(*missing, key)
	}
	return v
}

// missingConfigError formats the "every missing variable at once" error --
// same wording as cmd/stratium-pep/config.go's helper of the same name, for
// the same reason requiredEnv is duplicated rather than shared.
func missingConfigError(missing []string) error {
	return fmt.Errorf("missing required configuration: %s", strings.Join(missing, ", "))
}

// splitGroups splits a comma-separated group list, trimming surrounding
// whitespace and rejecting an empty entry (a leading, trailing, or doubled
// comma) rather than silently dropping it. Mirrors
// internal/config.splitPolicyLanguages exactly: this package cannot tell
// "typo" from "meant to write something here" apart, and here a silently
// dropped entry is worse than that function's own case -- a dropped policy
// language degrades to fewer engines, a dropped admin group name means an
// intended administrator is refused entirely, not merely under-privileged.
func splitGroups(envVar, v string) ([]string, error) {
	parts := strings.Split(v, ",")
	groups := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, fmt.Errorf("%s: empty group name in %q (check for a stray comma)", envVar, v)
		}
		groups = append(groups, p)
	}
	return groups, nil
}
