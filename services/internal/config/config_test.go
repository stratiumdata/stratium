package config

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// setValidEnv sets valid values for both required variables and clears the
// optional ones, so every test starts from a known-good baseline regardless
// of what happens to be set in the ambient environment. t.Setenv restores
// each variable after the test, so subtests never leak into one another.
func setValidEnv(t *testing.T) {
	t.Helper()
	t.Setenv("STRATIUM_DATABASE_URL", "postgres://localhost/stratium")
	t.Setenv("STRATIUM_TENANT_ID", "tenant-123")
	t.Setenv("STRATIUM_LISTEN_ADDR", "")
	t.Setenv("STRATIUM_MAX_DELEGATION_DEPTH", "")
	t.Setenv("STRATIUM_DB_TIMEOUT", "")
	t.Setenv("STRATIUM_MIGRATION_DATABASE_URL", "")
	t.Setenv("STRATIUM_POLICY_LANGUAGES", "")
}

// TestLoad_AllFieldsFromEnvironment compares field by field, not the whole
// struct by ==: Config now carries PolicyLanguages ([]string), and a struct
// with a slice field cannot be compared with == at all — the compiler
// rejects it, not just at the zero value.
func TestLoad_AllFieldsFromEnvironment(t *testing.T) {
	t.Setenv("STRATIUM_DATABASE_URL", "postgres://user:pass@localhost:5432/stratium")
	t.Setenv("STRATIUM_TENANT_ID", "tenant-abc")
	t.Setenv("STRATIUM_LISTEN_ADDR", ":9090")
	t.Setenv("STRATIUM_MAX_DELEGATION_DEPTH", "8")
	t.Setenv("STRATIUM_DB_TIMEOUT", "30s")
	t.Setenv("STRATIUM_MIGRATION_DATABASE_URL", "postgres://migrate:pass@localhost:5432/stratium")
	t.Setenv("STRATIUM_POLICY_LANGUAGES", "xacml,cedar")

	got, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if got.DatabaseURL != "postgres://user:pass@localhost:5432/stratium" {
		t.Errorf("DatabaseURL = %q", got.DatabaseURL)
	}
	if got.MigrationDatabaseURL != "postgres://migrate:pass@localhost:5432/stratium" {
		t.Errorf("MigrationDatabaseURL = %q", got.MigrationDatabaseURL)
	}
	if got.TenantID != "tenant-abc" {
		t.Errorf("TenantID = %q", got.TenantID)
	}
	if got.ListenAddr != ":9090" {
		t.Errorf("ListenAddr = %q", got.ListenAddr)
	}
	if got.MaxDepth != 8 {
		t.Errorf("MaxDepth = %d", got.MaxDepth)
	}
	if got.DBTimeout != 30*time.Second {
		t.Errorf("DBTimeout = %v", got.DBTimeout)
	}
	if want := []string{"xacml", "cedar"}; !slices.Equal(got.PolicyLanguages, want) {
		t.Errorf("PolicyLanguages = %v, want %v", got.PolicyLanguages, want)
	}
}

// STRATIUM_MIGRATION_DATABASE_URL is optional: leaving it unset must not
// error, and must leave the field empty so main.go's "skip migrations, log
// the assumption" branch has something to test against.
func TestLoad_MigrationDatabaseURLIsOptional(t *testing.T) {
	setValidEnv(t)

	got, err := Load()
	if err != nil {
		t.Fatalf("Load() with no STRATIUM_MIGRATION_DATABASE_URL returned error: %v", err)
	}
	if got.MigrationDatabaseURL != "" {
		t.Errorf("MigrationDatabaseURL = %q, want empty", got.MigrationDatabaseURL)
	}
}

// Set, it must come through — main.go branches on this being non-empty to
// decide whether to run migrations at all.
func TestLoad_MigrationDatabaseURLSetWhenProvided(t *testing.T) {
	setValidEnv(t)
	t.Setenv("STRATIUM_MIGRATION_DATABASE_URL", "postgres://migrate:pass@localhost:5432/stratium")

	got, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if got.MigrationDatabaseURL != "postgres://migrate:pass@localhost:5432/stratium" {
		t.Errorf("MigrationDatabaseURL = %q, want the configured URL", got.MigrationDatabaseURL)
	}
}

func TestLoad_Defaults(t *testing.T) {
	setValidEnv(t)

	got, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if got.ListenAddr != ":50051" {
		t.Errorf("ListenAddr = %q, want %q", got.ListenAddr, ":50051")
	}
	if got.MaxDepth != 5 {
		t.Errorf("MaxDepth = %d, want 5", got.MaxDepth)
	}
	if got.DBTimeout != 5*time.Second {
		t.Errorf("DBTimeout = %v, want %v", got.DBTimeout, 5*time.Second)
	}
}

func TestLoad_MissingDatabaseURL(t *testing.T) {
	setValidEnv(t)
	t.Setenv("STRATIUM_DATABASE_URL", "")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() with no STRATIUM_DATABASE_URL: want error, got nil")
	}
	if !strings.Contains(err.Error(), "STRATIUM_DATABASE_URL") {
		t.Fatalf("error %q does not name the missing variable", err.Error())
	}
}

func TestLoad_MissingTenantID(t *testing.T) {
	setValidEnv(t)
	t.Setenv("STRATIUM_TENANT_ID", "")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() with no STRATIUM_TENANT_ID: want error, got nil")
	}
	if !strings.Contains(err.Error(), "STRATIUM_TENANT_ID") {
		t.Fatalf("error %q does not name the missing variable", err.Error())
	}
}

// The tenant must fail closed even when every other variable, including the
// database URL, is present and valid. The tenant is startup configuration,
// never a request field — the predecessor system trusted a client-supplied
// x-user-id header instead, and that was a critical authentication bypass.
// There is no default here, and none should ever be added.
func TestLoad_TenantIDHasNoDefault(t *testing.T) {
	t.Setenv("STRATIUM_DATABASE_URL", "postgres://localhost/stratium")
	t.Setenv("STRATIUM_TENANT_ID", "")
	t.Setenv("STRATIUM_LISTEN_ADDR", "")
	t.Setenv("STRATIUM_MAX_DELEGATION_DEPTH", "")
	t.Setenv("STRATIUM_DB_TIMEOUT", "")
	t.Setenv("STRATIUM_MIGRATION_DATABASE_URL", "")
	t.Setenv("STRATIUM_POLICY_LANGUAGES", "")

	got, err := Load()
	if err == nil {
		t.Fatalf("Load() with no tenant: want error, got Config %+v", got)
	}
}

func TestLoad_MaxDelegationDepthBelowOne(t *testing.T) {
	for _, v := range []string{"0", "-1"} {
		t.Run(v, func(t *testing.T) {
			setValidEnv(t)
			t.Setenv("STRATIUM_MAX_DELEGATION_DEPTH", v)

			_, err := Load()
			if err == nil {
				t.Fatalf("Load() with STRATIUM_MAX_DELEGATION_DEPTH=%s: want error, got nil", v)
			}
		})
	}
}

func TestLoad_MaxDelegationDepthUnparseable(t *testing.T) {
	setValidEnv(t)
	t.Setenv("STRATIUM_MAX_DELEGATION_DEPTH", "not-a-number")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() with unparseable STRATIUM_MAX_DELEGATION_DEPTH: want error, got nil")
	}
	if !strings.Contains(err.Error(), "STRATIUM_MAX_DELEGATION_DEPTH") {
		t.Fatalf("error %q does not name the offending variable", err.Error())
	}
}

func TestLoad_DBTimeoutUnparseable(t *testing.T) {
	setValidEnv(t)
	t.Setenv("STRATIUM_DB_TIMEOUT", "not-a-duration")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() with unparseable STRATIUM_DB_TIMEOUT: want error, got nil")
	}
	if !strings.Contains(err.Error(), "STRATIUM_DB_TIMEOUT") {
		t.Fatalf("error %q does not name the offending variable", err.Error())
	}
}

// Unset must default to every language this build ships — the same
// "guessing nothing beats a silent partial deployment" reasoning as
// ListenAddr's default, applied to the policy engine set: an operator who
// never heard of this variable gets full functionality, not a PDP that
// silently denies every policy in three of four languages via D10's own
// orphan-language path (multi.go's orphanVerdict) without ever being told
// why.
func TestLoad_PolicyLanguagesDefault(t *testing.T) {
	setValidEnv(t)

	got, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	want := []string{"cedar", "json", "rego", "xacml"}
	if !slices.Equal(got.PolicyLanguages, want) {
		t.Errorf("PolicyLanguages = %v, want %v", got.PolicyLanguages, want)
	}
}

// Whitespace around an entry must not survive into the parsed list:
// "cedar, rego" is a deployment writing one value across a line wrap, not a
// deployment naming a language literally called " rego".
func TestLoad_PolicyLanguagesTrimsWhitespace(t *testing.T) {
	setValidEnv(t)
	t.Setenv("STRATIUM_POLICY_LANGUAGES", " cedar ,  rego")

	got, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if want := []string{"cedar", "rego"}; !slices.Equal(got.PolicyLanguages, want) {
		t.Errorf("PolicyLanguages = %v, want %v", got.PolicyLanguages, want)
	}
}

// A stray comma produces an empty entry, not a shorter list: this package
// cannot tell "typo" apart from "meant to write something here," so it
// fails closed rather than silently deploying with one fewer engine than
// its author believed they listed. This is syntactic validation only —
// config has no opinion on whether "cedar" or "cobol" is a real engine, see
// splitPolicyLanguages' own doc comment — so this test uses a blank entry,
// not an unimplemented language name (that belongs to
// cmd/stratium-pdp/registry_test.go, the package that actually knows which
// names are real).
func TestLoad_PolicyLanguagesEmptyEntry(t *testing.T) {
	setValidEnv(t)
	t.Setenv("STRATIUM_POLICY_LANGUAGES", "cedar,,rego")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() with an empty STRATIUM_POLICY_LANGUAGES entry: want error, got nil")
	}
	if !strings.Contains(err.Error(), "STRATIUM_POLICY_LANGUAGES") {
		t.Fatalf("error %q does not name the offending variable", err.Error())
	}
}
