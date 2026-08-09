package config

import (
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
}

func TestLoad_AllFieldsFromEnvironment(t *testing.T) {
	t.Setenv("STRATIUM_DATABASE_URL", "postgres://user:pass@localhost:5432/stratium")
	t.Setenv("STRATIUM_TENANT_ID", "tenant-abc")
	t.Setenv("STRATIUM_LISTEN_ADDR", ":9090")
	t.Setenv("STRATIUM_MAX_DELEGATION_DEPTH", "8")
	t.Setenv("STRATIUM_DB_TIMEOUT", "30s")
	t.Setenv("STRATIUM_MIGRATION_DATABASE_URL", "postgres://migrate:pass@localhost:5432/stratium")

	got, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	want := Config{
		DatabaseURL:          "postgres://user:pass@localhost:5432/stratium",
		MigrationDatabaseURL: "postgres://migrate:pass@localhost:5432/stratium",
		TenantID:             "tenant-abc",
		ListenAddr:           ":9090",
		MaxDepth:             8,
		DBTimeout:            30 * time.Second,
	}
	if got != want {
		t.Fatalf("Load() = %+v, want %+v", got, want)
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
