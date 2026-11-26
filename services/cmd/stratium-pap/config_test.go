package main

import (
	"strings"
	"testing"
	"time"
)

// requiredPAPEnvVars names every variable loadConfig requires with no
// default -- shared by clearPAPEnv/setAllPAPEnv below and the "missing
// variable" cases in TestLoadConfig, so a field added to Config without
// being added HERE goes untested for its own absence instead of failing
// loudly, the same guard cmd/stratium-pep/hook_test.go's
// requiredHookEnvVars gives that package.
var requiredPAPEnvVars = []string{
	"STRATIUM_PAP_TENANT_ID",
	"STRATIUM_PAP_OIDC_ISSUER",
	"STRATIUM_PAP_OIDC_AUDIENCE",
	"STRATIUM_PAP_OIDC_CLIENT_ID",
	"STRATIUM_PAP_ROLE_CLAIM",
	"STRATIUM_PAP_APPROVER_CLAIM",
	"STRATIUM_PAP_ADMIN_GROUPS",
	"STRATIUM_PAP_EDITOR_GROUPS",
	"STRATIUM_PAP_VIEWER_GROUPS",
	"STRATIUM_PAP_DATABASE_URL",
}

func clearPAPEnv(t *testing.T) {
	t.Helper()
	for _, k := range requiredPAPEnvVars {
		t.Setenv(k, "")
	}
	t.Setenv("STRATIUM_PAP_LISTEN_ADDR", "")
	t.Setenv("STRATIUM_PAP_OIDC_TIMEOUT", "")
	t.Setenv("STRATIUM_PAP_OIDC_SCOPE", "")
	t.Setenv("STRATIUM_PAP_DB_TIMEOUT", "")
	t.Setenv("STRATIUM_PAP_DB_MAX_OPEN_CONNS", "")
	t.Setenv("STRATIUM_PAP_OIDC_KEY_REFRESH_INTERVAL", "")
}

func setAllPAPEnv(t *testing.T, overrides map[string]string) {
	t.Helper()
	values := map[string]string{
		"STRATIUM_PAP_TENANT_ID":      "tenant-one",
		"STRATIUM_PAP_OIDC_ISSUER":    "https://idp.example.com/",
		"STRATIUM_PAP_OIDC_AUDIENCE":  "stratium-pap",
		"STRATIUM_PAP_OIDC_CLIENT_ID": "stratium-pap-ui",
		"STRATIUM_PAP_ROLE_CLAIM":     "roles",
		"STRATIUM_PAP_APPROVER_CLAIM": "email",
		"STRATIUM_PAP_ADMIN_GROUPS":   "org-admins",
		"STRATIUM_PAP_EDITOR_GROUPS":  "org-editors",
		"STRATIUM_PAP_VIEWER_GROUPS":  "org-everyone",
		"STRATIUM_PAP_DATABASE_URL":   "postgres://stratium_pap_login:secret@localhost:5432/stratium?sslmode=disable",
	}
	for k, v := range overrides {
		values[k] = v
	}
	for _, k := range requiredPAPEnvVars {
		t.Setenv(k, values[k])
	}
}

func TestLoadConfig(t *testing.T) {
	t.Run("all required set, defaults applied", func(t *testing.T) {
		clearPAPEnv(t)
		setAllPAPEnv(t, nil)

		cfg, err := loadConfig()
		if err != nil {
			t.Fatalf("loadConfig() error = %v, want nil", err)
		}
		if cfg.TenantID != "tenant-one" {
			t.Errorf("TenantID = %q, want %q", cfg.TenantID, "tenant-one")
		}
		if cfg.OIDCIssuer != "https://idp.example.com/" {
			t.Errorf("OIDCIssuer = %q, want %q", cfg.OIDCIssuer, "https://idp.example.com/")
		}
		if cfg.OIDCAudience != "stratium-pap" {
			t.Errorf("OIDCAudience = %q, want %q", cfg.OIDCAudience, "stratium-pap")
		}
		if cfg.RoleClaim != "roles" {
			t.Errorf("RoleClaim = %q, want %q", cfg.RoleClaim, "roles")
		}
		if cfg.OIDCClientID != "stratium-pap-ui" {
			t.Errorf("OIDCClientID = %q, want %q", cfg.OIDCClientID, "stratium-pap-ui")
		}
		// Defaulted, unlike the client id: see Config.OIDCScope's own comment.
		if cfg.OIDCScope != defaultOIDCScope {
			t.Errorf("OIDCScope = %q, want the default %q", cfg.OIDCScope, defaultOIDCScope)
		}
		if cfg.ApproverClaim != "email" {
			t.Errorf("ApproverClaim = %q, want %q", cfg.ApproverClaim, "email")
		}
		wantRoles := RoleMapping{"org-admins": RoleAdmin, "org-editors": RoleEditor, "org-everyone": RoleViewer}
		if len(cfg.Roles) != len(wantRoles) {
			t.Fatalf("Roles = %v, want %v", cfg.Roles, wantRoles)
		}
		for k, v := range wantRoles {
			if cfg.Roles[k] != v {
				t.Errorf("Roles[%q] = %q, want %q", k, cfg.Roles[k], v)
			}
		}
		if cfg.ListenAddr != ":8080" {
			t.Errorf("ListenAddr = %q, want default %q", cfg.ListenAddr, ":8080")
		}
		if cfg.OIDCTimeout != 5*time.Second {
			t.Errorf("OIDCTimeout = %v, want default %v", cfg.OIDCTimeout, 5*time.Second)
		}
		if cfg.DatabaseURL != "postgres://stratium_pap_login:secret@localhost:5432/stratium?sslmode=disable" {
			t.Errorf("DatabaseURL = %q, want the configured value", cfg.DatabaseURL)
		}
		if cfg.DBTimeout != 5*time.Second {
			t.Errorf("DBTimeout = %v, want default %v", cfg.DBTimeout, 5*time.Second)
		}
	})

	t.Run("listen addr, oidc timeout, and db timeout are configurable", func(t *testing.T) {
		clearPAPEnv(t)
		setAllPAPEnv(t, nil)
		t.Setenv("STRATIUM_PAP_LISTEN_ADDR", ":9443")
		t.Setenv("STRATIUM_PAP_OIDC_TIMEOUT", "2s")
		t.Setenv("STRATIUM_PAP_DB_TIMEOUT", "3s")

		cfg, err := loadConfig()
		if err != nil {
			t.Fatalf("loadConfig() error = %v, want nil", err)
		}
		if cfg.ListenAddr != ":9443" {
			t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, ":9443")
		}
		if cfg.OIDCTimeout != 2*time.Second {
			t.Errorf("OIDCTimeout = %v, want %v", cfg.OIDCTimeout, 2*time.Second)
		}
		if cfg.DBTimeout != 3*time.Second {
			t.Errorf("DBTimeout = %v, want %v", cfg.DBTimeout, 3*time.Second)
		}
	})

	// The property the task brief asks for by name: a missing config value
	// fails startup naming every missing key, not just the first one
	// encountered. Every required variable, one at a time, so a field added
	// to Config without a matching presence check in loadConfig fails here
	// rather than only on an operator's first deploy.
	t.Run("each required variable is named when missing alone", func(t *testing.T) {
		for _, missingVar := range requiredPAPEnvVars {
			t.Run(missingVar, func(t *testing.T) {
				clearPAPEnv(t)
				setAllPAPEnv(t, nil)
				t.Setenv(missingVar, "")

				_, err := loadConfig()
				if err == nil {
					t.Fatalf("loadConfig() error = nil, want an error naming %s", missingVar)
				}
				if !strings.Contains(err.Error(), missingVar) {
					t.Errorf("error = %q, want it to name %s", err.Error(), missingVar)
				}
			})
		}
	})

	// The exact property the brief requires verbatim: EVERY missing key is
	// named from ONE run, not discovered one restart at a time. A config
	// loader that fails fast on the first missing variable (returns before
	// checking the rest) would pass every subtest above individually while
	// failing this one -- it is what actually distinguishes "checks each
	// field" from "collects every gap before returning," the fix
	// cmd/stratium-pep/config.go's combineConfigErrors applied across two
	// loaders and PDP's internal/config.Load applies within one struct.
	t.Run("every missing key is named at once", func(t *testing.T) {
		clearPAPEnv(t)

		_, err := loadConfig()
		if err == nil {
			t.Fatal("loadConfig() error = nil, want an error naming every required variable")
		}
		for _, k := range requiredPAPEnvVars {
			if !strings.Contains(err.Error(), k) {
				t.Errorf("error = %q, want it to also name %s", err.Error(), k)
			}
		}
	})

	// A group value cannot silently mean two roles at once -- see
	// newRoleMapping's own test for the pure-function version of this;
	// this confirms loadConfig actually wires group parsing through it
	// rather than, say, only calling it for the admin list.
	t.Run("a group mapped to two roles fails startup", func(t *testing.T) {
		clearPAPEnv(t)
		setAllPAPEnv(t, map[string]string{
			"STRATIUM_PAP_ADMIN_GROUPS":  "org-staff",
			"STRATIUM_PAP_EDITOR_GROUPS": "org-staff",
		})

		_, err := loadConfig()
		if err == nil {
			t.Fatal("loadConfig() error = nil, want an error naming the group mapped twice")
		}
		if !strings.Contains(err.Error(), "org-staff") {
			t.Errorf("error = %q, want it to name org-staff", err.Error())
		}
	})

	// A comma-separated group list with a stray comma silently drops a
	// group name rather than naming it -- internal/config's
	// splitPolicyLanguages rejects this shape for STRATIUM_POLICY_LANGUAGES
	// for the same reason; PAP's own group lists get the same treatment
	// since a dropped admin group here is worse (an intended admin gets no
	// role and is refused entirely, not silently under-privileged).
	t.Run("a stray comma in a group list fails startup", func(t *testing.T) {
		clearPAPEnv(t)
		setAllPAPEnv(t, map[string]string{"STRATIUM_PAP_ADMIN_GROUPS": "org-admins,,org-root"})

		_, err := loadConfig()
		if err == nil {
			t.Fatal("loadConfig() error = nil, want an error on the empty entry")
		}
		if !strings.Contains(err.Error(), "STRATIUM_PAP_ADMIN_GROUPS") {
			t.Errorf("error = %q, want it to name STRATIUM_PAP_ADMIN_GROUPS", err.Error())
		}
	})

	t.Run("a non-positive oidc timeout fails startup", func(t *testing.T) {
		clearPAPEnv(t)
		setAllPAPEnv(t, nil)
		t.Setenv("STRATIUM_PAP_OIDC_TIMEOUT", "0s")

		_, err := loadConfig()
		if err == nil {
			t.Fatal("loadConfig() error = nil, want an error rejecting a non-positive timeout")
		}
	})

	t.Run("an unparseable oidc timeout fails startup", func(t *testing.T) {
		clearPAPEnv(t)
		setAllPAPEnv(t, nil)
		t.Setenv("STRATIUM_PAP_OIDC_TIMEOUT", "not-a-duration")

		_, err := loadConfig()
		if err == nil {
			t.Fatal("loadConfig() error = nil, want an error on the unparseable duration")
		}
	})

	t.Run("a non-positive db timeout fails startup", func(t *testing.T) {
		clearPAPEnv(t)
		setAllPAPEnv(t, nil)
		t.Setenv("STRATIUM_PAP_DB_TIMEOUT", "0s")

		_, err := loadConfig()
		if err == nil {
			t.Fatal("loadConfig() error = nil, want an error rejecting a non-positive db timeout")
		}
	})

	t.Run("an unparseable db timeout fails startup", func(t *testing.T) {
		clearPAPEnv(t)
		setAllPAPEnv(t, nil)
		t.Setenv("STRATIUM_PAP_DB_TIMEOUT", "not-a-duration")

		_, err := loadConfig()
		if err == nil {
			t.Fatal("loadConfig() error = nil, want an error on the unparseable db timeout duration")
		}
	})
}

func TestLoadConfig_DBMaxOpenConns(t *testing.T) {
	clearPAPEnv(t)
	setAllPAPEnv(t, nil)
	t.Setenv("STRATIUM_PAP_DB_MAX_OPEN_CONNS", "")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if cfg.DBMaxOpenConns != 10 {
		t.Errorf("default DBMaxOpenConns = %d, want 10", cfg.DBMaxOpenConns)
	}

	t.Setenv("STRATIUM_PAP_DB_MAX_OPEN_CONNS", "25")
	if cfg, err = loadConfig(); err != nil || cfg.DBMaxOpenConns != 25 {
		t.Errorf("loadConfig() = %d, %v; want 25, nil", cfg.DBMaxOpenConns, err)
	}

	for _, bad := range []string{"0", "-1", "1.5", "many"} {
		t.Setenv("STRATIUM_PAP_DB_MAX_OPEN_CONNS", bad)
		if _, err := loadConfig(); err == nil || !strings.Contains(err.Error(), "STRATIUM_PAP_DB_MAX_OPEN_CONNS") {
			t.Errorf("value %q: loadConfig() error = %v, want one naming STRATIUM_PAP_DB_MAX_OPEN_CONNS", bad, err)
		}
	}
}

func TestLoadConfig_OIDCKeyRefresh(t *testing.T) {
	clearPAPEnv(t)
	setAllPAPEnv(t, nil)
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if cfg.OIDCKeyRefresh != 30*time.Second {
		t.Errorf("default OIDCKeyRefresh = %s, want 30s", cfg.OIDCKeyRefresh)
	}

	t.Setenv("STRATIUM_PAP_OIDC_KEY_REFRESH_INTERVAL", "2m")
	if cfg, err = loadConfig(); err != nil || cfg.OIDCKeyRefresh != 2*time.Minute {
		t.Errorf("loadConfig() = %s, %v; want 2m, nil", cfg.OIDCKeyRefresh, err)
	}

	for _, bad := range []string{"0s", "-1s", "often"} {
		t.Setenv("STRATIUM_PAP_OIDC_KEY_REFRESH_INTERVAL", bad)
		if _, err := loadConfig(); err == nil || !strings.Contains(err.Error(), "STRATIUM_PAP_OIDC_KEY_REFRESH_INTERVAL") {
			t.Errorf("value %q: loadConfig() error = %v, want one naming the variable", bad, err)
		}
	}
}
