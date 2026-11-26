package config

import (
	"slices"
	"strconv"
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
	t.Setenv("STRATIUM_APPROVAL_TTL", "")
	t.Setenv("STRATIUM_SPENT_PROOF_REAP_INTERVAL", "")
	t.Setenv("STRATIUM_MIGRATION_DATABASE_URL", "")
	t.Setenv("STRATIUM_POLICY_LANGUAGES", "")
	// Required with no default (spec §4.7.2 K9), so the known-good baseline
	// has to carry one or every test in this file would fail on the missing
	// variable rather than on its own subject.
	t.Setenv("STRATIUM_DPOP_FRESHNESS_WINDOW", "30s")
	// A placeholder, not a real key file: this package checks presence only
	// (see Load's own comment on TokenSigningKeyPath — opening and parsing
	// the file is internal/token.Load's job, exercised by that package's own
	// tests), so nothing here ever reads what this path names.
	t.Setenv("STRATIUM_TOKEN_SIGNING_KEY_PATH", "/test/current-key.pem")
	t.Setenv("STRATIUM_TOKEN_PREVIOUS_KEY_PATH", "")
	// TLS is required by default; placeholders, since Load checks presence
	// only and cmd/stratium-pdp is what reads the files.
	t.Setenv("STRATIUM_TLS_CERT_FILE", "/test/tls.crt")
	t.Setenv("STRATIUM_TLS_KEY_FILE", "/test/tls.key")
	t.Setenv("STRATIUM_GRPC_INSECURE", "")
	// Principal authentication is required by default too.
	t.Setenv("STRATIUM_PRINCIPAL_OIDC_ISSUER", "https://idp.example/realms/test")
	t.Setenv("STRATIUM_PRINCIPAL_OIDC_AUDIENCE", "stratium")
	t.Setenv("STRATIUM_PRINCIPAL_CLAIM", "email")
	t.Setenv("STRATIUM_PRINCIPAL_OIDC_TIMEOUT", "")
	t.Setenv("STRATIUM_PRINCIPAL_AUTH_INSECURE", "")
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
	t.Setenv("STRATIUM_APPROVAL_TTL", "48h")
	t.Setenv("STRATIUM_DPOP_FRESHNESS_WINDOW", "90s")
	t.Setenv("STRATIUM_SPENT_PROOF_REAP_INTERVAL", "12m")
	t.Setenv("STRATIUM_MIGRATION_DATABASE_URL", "postgres://migrate:pass@localhost:5432/stratium")
	t.Setenv("STRATIUM_POLICY_LANGUAGES", "xacml,cedar")
	t.Setenv("STRATIUM_TOKEN_SIGNING_KEY_PATH", "/keys/current.pem")
	t.Setenv("STRATIUM_TOKEN_PREVIOUS_KEY_PATH", "/keys/previous.pem")
	t.Setenv("STRATIUM_TLS_CERT_FILE", "/tls/pdp.crt")
	t.Setenv("STRATIUM_TLS_KEY_FILE", "/tls/pdp.key")
	t.Setenv("STRATIUM_GRPC_INSECURE", "")
	t.Setenv("STRATIUM_PRINCIPAL_OIDC_ISSUER", "https://idp.example/realms/prod")
	t.Setenv("STRATIUM_PRINCIPAL_OIDC_AUDIENCE", "stratium-pdp")
	t.Setenv("STRATIUM_PRINCIPAL_CLAIM", "preferred_username")
	t.Setenv("STRATIUM_PRINCIPAL_OIDC_TIMEOUT", "9s")
	t.Setenv("STRATIUM_PRINCIPAL_AUTH_INSECURE", "")

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
	if got.TokenSigningKeyPath != "/keys/current.pem" {
		t.Errorf("TokenSigningKeyPath = %q", got.TokenSigningKeyPath)
	}
	if got.TokenPreviousKeyPath != "/keys/previous.pem" {
		t.Errorf("TokenPreviousKeyPath = %q", got.TokenPreviousKeyPath)
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
	if got.ApprovalTTL != 48*time.Hour {
		t.Errorf("ApprovalTTL = %v", got.ApprovalTTL)
	}
	if got.DPoPFreshnessWindow != 90*time.Second {
		t.Errorf("DPoPFreshnessWindow = %v", got.DPoPFreshnessWindow)
	}
	if got.SpentProofReapInterval != 12*time.Minute {
		t.Errorf("SpentProofReapInterval = %v", got.SpentProofReapInterval)
	}
	if want := []string{"xacml", "cedar"}; !slices.Equal(got.PolicyLanguages, want) {
		t.Errorf("PolicyLanguages = %v, want %v", got.PolicyLanguages, want)
	}
	if got.PrincipalOIDCIssuer != "https://idp.example/realms/prod" || got.PrincipalOIDCAudience != "stratium-pdp" ||
		got.PrincipalClaim != "preferred_username" || got.PrincipalOIDCTimeout != 9*time.Second || got.PrincipalAuthInsecure {
		t.Errorf("principal auth = %q/%q/%q/%s insecure=%v", got.PrincipalOIDCIssuer, got.PrincipalOIDCAudience,
			got.PrincipalClaim, got.PrincipalOIDCTimeout, got.PrincipalAuthInsecure)
	}
	if got.TLSCertFile != "/tls/pdp.crt" || got.TLSKeyFile != "/tls/pdp.key" || got.GRPCInsecure {
		t.Errorf("transport = %q/%q insecure=%v", got.TLSCertFile, got.TLSKeyFile, got.GRPCInsecure)
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
	if got.ApprovalTTL != 24*time.Hour {
		t.Errorf("ApprovalTTL = %v, want %v", got.ApprovalTTL, 24*time.Hour)
	}
	if got.SpentProofReapInterval != 5*time.Minute {
		t.Errorf("SpentProofReapInterval = %v, want %v", got.SpentProofReapInterval, 5*time.Minute)
	}
	// DPoPFreshnessWindow is deliberately NOT asserted here: it has no
	// default to assert (K9), and setValidEnv supplies one only so the rest
	// of this test can run. TestLoad_MissingDPoPFreshnessWindow below is
	// where its absence of a default is the property.
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

// STRATIUM_TOKEN_SIGNING_KEY_PATH has no default, the same treatment as
// STRATIUM_DATABASE_URL and STRATIUM_TENANT_ID above: a PDP that starts
// without a configured signing key would go on to fail every decision it
// makes once tokens are wired in, in a way indistinguishable from a policy
// problem — that must be a startup failure instead.
func TestLoad_MissingTokenSigningKeyPath(t *testing.T) {
	setValidEnv(t)
	t.Setenv("STRATIUM_TOKEN_SIGNING_KEY_PATH", "")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() with no STRATIUM_TOKEN_SIGNING_KEY_PATH: want error, got nil")
	}
	if !strings.Contains(err.Error(), "STRATIUM_TOKEN_SIGNING_KEY_PATH") {
		t.Fatalf("error %q does not name the missing variable", err.Error())
	}
}

// Leaving STRATIUM_TOKEN_PREVIOUS_KEY_PATH unset must not error, and must
// leave the field empty: that is how internal/token.Load is told "no
// previous key," the ordinary state outside a rotation window, not a
// misconfiguration.
func TestLoad_TokenPreviousKeyPathIsOptional(t *testing.T) {
	setValidEnv(t)

	got, err := Load()
	if err != nil {
		t.Fatalf("Load() with no STRATIUM_TOKEN_PREVIOUS_KEY_PATH returned error: %v", err)
	}
	if got.TokenPreviousKeyPath != "" {
		t.Errorf("TokenPreviousKeyPath = %q, want empty", got.TokenPreviousKeyPath)
	}
}

// The property the brief is built around: a missing required value is
// reported alongside every OTHER missing required value, not just the first
// one Load happens to check. Four required variables unset at once (a
// freshly cloned deployment with none of the PDP's environment configured
// yet is exactly this case) must produce ONE error naming all four, so
// fixing configuration takes one read of one error message, not three
// restarts each revealing the next gap in turn.
func TestLoad_MissingMultipleRequired_NamesAllAtOnce(t *testing.T) {
	setValidEnv(t)
	t.Setenv("STRATIUM_DATABASE_URL", "")
	t.Setenv("STRATIUM_TENANT_ID", "")
	t.Setenv("STRATIUM_TOKEN_SIGNING_KEY_PATH", "")
	t.Setenv("STRATIUM_DPOP_FRESHNESS_WINDOW", "")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() with four required variables unset: want error, got nil")
	}
	for _, want := range []string{
		"STRATIUM_DATABASE_URL", "STRATIUM_TENANT_ID",
		"STRATIUM_TOKEN_SIGNING_KEY_PATH", "STRATIUM_DPOP_FRESHNESS_WINDOW",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %s alongside the other missing variables", err.Error(), want)
		}
	}
}

// The tenant must fail closed even when every other variable, including the
// database URL, is present and valid. The tenant is startup configuration,
// never a request field — the predecessor system trusted a client-supplied
// x-user-id header instead, and that was a critical authentication bypass.
// There is no default here, and none should ever be added.
//
// Sets every other required value explicitly (rather than calling
// setValidEnv) so TenantID is the ONLY gap: with the "name every missing
// variable at once" behavior Load now has, a test that left a second
// required value unset too would still see a non-nil error and pass for the
// wrong reason, never actually proving TenantID has no default.
func TestLoad_TenantIDHasNoDefault(t *testing.T) {
	t.Setenv("STRATIUM_DATABASE_URL", "postgres://localhost/stratium")
	t.Setenv("STRATIUM_TENANT_ID", "")
	t.Setenv("STRATIUM_TOKEN_SIGNING_KEY_PATH", "/test/current-key.pem")
	t.Setenv("STRATIUM_LISTEN_ADDR", "")
	t.Setenv("STRATIUM_MAX_DELEGATION_DEPTH", "")
	t.Setenv("STRATIUM_DB_TIMEOUT", "")
	t.Setenv("STRATIUM_MIGRATION_DATABASE_URL", "")
	t.Setenv("STRATIUM_POLICY_LANGUAGES", "")

	got, err := Load()
	if err == nil {
		t.Fatalf("Load() with no tenant: want error, got Config %+v", got)
	}
	if !strings.Contains(err.Error(), "STRATIUM_TENANT_ID") {
		t.Fatalf("error %q does not name the missing variable", err.Error())
	}
	if strings.Contains(err.Error(), "STRATIUM_DATABASE_URL") || strings.Contains(err.Error(), "STRATIUM_TOKEN_SIGNING_KEY_PATH") {
		t.Fatalf("error %q names a variable that WAS set; this test isolates TenantID alone", err.Error())
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

func TestLoad_ApprovalTTLUnparseable(t *testing.T) {
	setValidEnv(t)
	t.Setenv("STRATIUM_APPROVAL_TTL", "not-a-duration")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() with unparseable STRATIUM_APPROVAL_TTL: want error, got nil")
	}
	if !strings.Contains(err.Error(), "STRATIUM_APPROVAL_TTL") {
		t.Fatalf("error %q does not name the offending variable", err.Error())
	}
}

// A zero or negative TTL would mint an approval that is already expired at
// the instant CreateApproval creates it (Verify's expiry check is strict:
// now must be BEFORE expires_at, never equal) — every escalation would then
// deny "expired" no matter how fast the control plane responded. This must
// fail at startup, not surface later as a mystifying, silent 100% denial
// rate on every retry.
func TestLoad_ApprovalTTLNotPositive(t *testing.T) {
	for _, v := range []string{"0s", "-1h"} {
		t.Run(v, func(t *testing.T) {
			setValidEnv(t)
			t.Setenv("STRATIUM_APPROVAL_TTL", v)

			_, err := Load()
			if err == nil {
				t.Fatalf("Load() with STRATIUM_APPROVAL_TTL=%s: want error, got nil", v)
			}
			if !strings.Contains(err.Error(), "STRATIUM_APPROVAL_TTL") {
				t.Fatalf("error %q does not name the offending variable", err.Error())
			}
		})
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

// TestLoad_MissingDPoPFreshnessWindow is spec §4.7.2 K9's "required
// configuration with no default", stated as the same fail-closed property
// TestLoad_TenantIDHasNoDefault states for the tenant.
//
// Every other required value is set explicitly rather than through
// setValidEnv, for the reason TestLoad_TenantIDHasNoDefault spells out: with
// "name every missing variable at once" behaviour, a test that left a second
// gap open would still see a non-nil error and pass for the wrong reason,
// never proving THIS variable has no default. The assertion on the returned
// Config is what makes it specific — a Load that silently defaulted the
// window would return nil and a non-zero duration, and only checking both
// catches it.
func TestLoad_MissingDPoPFreshnessWindow(t *testing.T) {
	t.Setenv("STRATIUM_DATABASE_URL", "postgres://localhost/stratium")
	t.Setenv("STRATIUM_TENANT_ID", "tenant-123")
	t.Setenv("STRATIUM_TOKEN_SIGNING_KEY_PATH", "/test/current-key.pem")
	t.Setenv("STRATIUM_DPOP_FRESHNESS_WINDOW", "")
	t.Setenv("STRATIUM_LISTEN_ADDR", "")
	t.Setenv("STRATIUM_MAX_DELEGATION_DEPTH", "")
	t.Setenv("STRATIUM_DB_TIMEOUT", "")
	t.Setenv("STRATIUM_APPROVAL_TTL", "")
	t.Setenv("STRATIUM_SPENT_PROOF_REAP_INTERVAL", "")
	t.Setenv("STRATIUM_MIGRATION_DATABASE_URL", "")
	t.Setenv("STRATIUM_POLICY_LANGUAGES", "")
	t.Setenv("STRATIUM_TOKEN_PREVIOUS_KEY_PATH", "")

	got, err := Load()
	if err == nil {
		t.Fatalf("Load() with no STRATIUM_DPOP_FRESHNESS_WINDOW: want error, got nil "+
			"(DPoPFreshnessWindow = %v) — K9 gives this value no default at any level", got.DPoPFreshnessWindow)
	}
	if !strings.Contains(err.Error(), "STRATIUM_DPOP_FRESHNESS_WINDOW") {
		t.Fatalf("error %q does not name the missing variable", err.Error())
	}
}

func TestLoad_DPoPFreshnessWindowUnparseable(t *testing.T) {
	setValidEnv(t)
	t.Setenv("STRATIUM_DPOP_FRESHNESS_WINDOW", "thirty seconds")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() with an unparseable STRATIUM_DPOP_FRESHNESS_WINDOW: want error, got nil")
	}
	if !strings.Contains(err.Error(), "STRATIUM_DPOP_FRESHNESS_WINDOW") {
		t.Fatalf("error %q does not name the offending variable", err.Error())
	}
	// A malformed value must not be reported as a MISSING one: the two have
	// different fixes (correct the syntax vs. supply the variable), and the
	// missing-variable path is the one that runs first, so a check placed on
	// the wrong side of it would collapse them.
	if strings.Contains(err.Error(), "missing required configuration") {
		t.Errorf("error %q reports a malformed value as a missing one", err.Error())
	}
}

// A non-positive window is refused at startup rather than half-enforced:
// internal/dpop.Verify's own doc comment records that window == 0 does NOT
// fail closed by itself — a proof whose iat lands on the same second as now
// satisfies both freshness comparisons and verifies. An operator who wrote 0
// meaning "as strict as possible" would get the opposite.
func TestLoad_DPoPFreshnessWindowNotPositive(t *testing.T) {
	for _, v := range []string{"0s", "-30s"} {
		t.Run(v, func(t *testing.T) {
			setValidEnv(t)
			t.Setenv("STRATIUM_DPOP_FRESHNESS_WINDOW", v)

			_, err := Load()
			if err == nil {
				t.Fatalf("Load() with STRATIUM_DPOP_FRESHNESS_WINDOW=%s: want error, got nil", v)
			}
			if !strings.Contains(err.Error(), "STRATIUM_DPOP_FRESHNESS_WINDOW") {
				t.Fatalf("error %q does not name the offending variable", err.Error())
			}
		})
	}
}

func TestLoad_SpentProofReapIntervalUnparseable(t *testing.T) {
	setValidEnv(t)
	t.Setenv("STRATIUM_SPENT_PROOF_REAP_INTERVAL", "every 5 minutes")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() with an unparseable STRATIUM_SPENT_PROOF_REAP_INTERVAL: want error, got nil")
	}
	if !strings.Contains(err.Error(), "STRATIUM_SPENT_PROOF_REAP_INTERVAL") {
		t.Fatalf("error %q does not name the offending variable", err.Error())
	}
}

// A non-positive interval would panic time.NewTicker in cmd/stratium-pdp's
// reapSpentProofs — a crash at startup rather than a config error, and one
// whose stack trace names time, not this variable.
func TestLoad_SpentProofReapIntervalNotPositive(t *testing.T) {
	for _, v := range []string{"0s", "-5m"} {
		t.Run(v, func(t *testing.T) {
			setValidEnv(t)
			t.Setenv("STRATIUM_SPENT_PROOF_REAP_INTERVAL", v)

			_, err := Load()
			if err == nil {
				t.Fatalf("Load() with STRATIUM_SPENT_PROOF_REAP_INTERVAL=%s: want error, got nil", v)
			}
			if !strings.Contains(err.Error(), "STRATIUM_SPENT_PROOF_REAP_INTERVAL") {
				t.Fatalf("error %q does not name the offending variable", err.Error())
			}
		})
	}
}

func TestLoad_FailedTokenAuditRate(t *testing.T) {
	setValidEnv(t)
	t.Setenv("STRATIUM_FAILED_TOKEN_AUDIT_PER_SECOND", "")
	t.Setenv("STRATIUM_FAILED_TOKEN_AUDIT_BURST", "")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if c.FailedTokenAuditPerSecond != 5 || c.FailedTokenAuditBurst != 20 {
		t.Errorf("defaults = %v per second, burst %d; want 5 and 20", c.FailedTokenAuditPerSecond, c.FailedTokenAuditBurst)
	}

	t.Setenv("STRATIUM_FAILED_TOKEN_AUDIT_PER_SECOND", "0.5")
	t.Setenv("STRATIUM_FAILED_TOKEN_AUDIT_BURST", "3")
	if c, err = Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if c.FailedTokenAuditPerSecond != 0.5 || c.FailedTokenAuditBurst != 3 {
		t.Errorf("got %v per second, burst %d; want 0.5 and 3", c.FailedTokenAuditPerSecond, c.FailedTokenAuditBurst)
	}

	for _, bad := range [][2]string{
		{"STRATIUM_FAILED_TOKEN_AUDIT_PER_SECOND", "0"},
		{"STRATIUM_FAILED_TOKEN_AUDIT_PER_SECOND", "-1"},
		{"STRATIUM_FAILED_TOKEN_AUDIT_PER_SECOND", "NaN"},
		{"STRATIUM_FAILED_TOKEN_AUDIT_PER_SECOND", "+Inf"},
		{"STRATIUM_FAILED_TOKEN_AUDIT_PER_SECOND", "fast"},
		{"STRATIUM_FAILED_TOKEN_AUDIT_BURST", "0"},
		{"STRATIUM_FAILED_TOKEN_AUDIT_BURST", "1.5"},
	} {
		t.Run(bad[0]+"="+bad[1], func(t *testing.T) {
			t.Setenv("STRATIUM_FAILED_TOKEN_AUDIT_PER_SECOND", "")
			t.Setenv("STRATIUM_FAILED_TOKEN_AUDIT_BURST", "")
			t.Setenv(bad[0], bad[1])
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), bad[0]) {
				t.Errorf("Load() error = %v, want one naming %s", err, bad[0])
			}
		})
	}
}

func TestLoad_DBMaxOpenConns(t *testing.T) {
	setValidEnv(t)
	t.Setenv("STRATIUM_DB_MAX_OPEN_CONNS", "")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if c.DBMaxOpenConns != 20 {
		t.Errorf("default DBMaxOpenConns = %d, want 20", c.DBMaxOpenConns)
	}

	t.Setenv("STRATIUM_DB_MAX_OPEN_CONNS", "50")
	if c, err = Load(); err != nil || c.DBMaxOpenConns != 50 {
		t.Errorf("Load() = %d, %v; want 50, nil", c.DBMaxOpenConns, err)
	}

	for _, bad := range []string{"0", "-1", "1.5", "many"} {
		t.Setenv("STRATIUM_DB_MAX_OPEN_CONNS", bad)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "STRATIUM_DB_MAX_OPEN_CONNS") {
			t.Errorf("value %q: Load() error = %v, want one naming STRATIUM_DB_MAX_OPEN_CONNS", bad, err)
		}
	}
}

func TestLoad_RequestTimeout(t *testing.T) {
	setValidEnv(t)
	t.Setenv("STRATIUM_REQUEST_TIMEOUT", "")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if c.RequestTimeout != 10*time.Second {
		t.Errorf("default RequestTimeout = %s, want 10s", c.RequestTimeout)
	}

	t.Setenv("STRATIUM_REQUEST_TIMEOUT", "30s")
	if c, err = Load(); err != nil || c.RequestTimeout != 30*time.Second {
		t.Errorf("Load() = %s, %v; want 30s, nil", c.RequestTimeout, err)
	}

	for _, bad := range []string{"0s", "-1s", "soon"} {
		t.Setenv("STRATIUM_REQUEST_TIMEOUT", bad)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "STRATIUM_REQUEST_TIMEOUT") {
			t.Errorf("value %q: Load() error = %v, want one naming STRATIUM_REQUEST_TIMEOUT", bad, err)
		}
	}
}

func TestLoad_MaxRequestBytes(t *testing.T) {
	setValidEnv(t)
	t.Setenv("STRATIUM_MAX_REQUEST_BYTES", "")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if c.MaxRequestBytes != 4<<20 {
		t.Errorf("default MaxRequestBytes = %d, want %d", c.MaxRequestBytes, 4<<20)
	}

	t.Setenv("STRATIUM_MAX_REQUEST_BYTES", "1048576")
	if c, err = Load(); err != nil || c.MaxRequestBytes != 1<<20 {
		t.Errorf("Load() = %d, %v; want %d, nil", c.MaxRequestBytes, err, 1<<20)
	}

	for _, bad := range []string{"0", "-1", "1MiB"} {
		t.Setenv("STRATIUM_MAX_REQUEST_BYTES", bad)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "STRATIUM_MAX_REQUEST_BYTES") {
			t.Errorf("value %q: Load() error = %v, want one naming STRATIUM_MAX_REQUEST_BYTES", bad, err)
		}
	}
}

func TestLoad_RequestLimits(t *testing.T) {
	names := []string{
		"STRATIUM_MAX_TOOL_BYTES", "STRATIUM_MAX_NAME_BYTES", "STRATIUM_MAX_SUBJECT_BYTES",
		"STRATIUM_MAX_PATH_BYTES", "STRATIUM_MAX_URI_BYTES", "STRATIUM_MAX_PURPOSE_BYTES",
		"STRATIUM_MAX_CREDENTIAL_BYTES", "STRATIUM_MAX_REQUESTED_TOOLS", "STRATIUM_MAX_RESOURCE_ENTRIES",
	}
	setValidEnv(t)
	for _, n := range names {
		t.Setenv(n, "")
	}
	c, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if c.Limits != DefaultRequestLimits() {
		t.Errorf("Limits = %+v, want the defaults %+v", c.Limits, DefaultRequestLimits())
	}

	// Each variable sets its own limit and no other: give every one a
	// different value and read them all back.
	for i, n := range names {
		t.Setenv(n, strconv.Itoa(100+i))
	}
	if c, err = Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := RequestLimits{
		ToolBytes: 100, NameBytes: 101, SubjectBytes: 102, PathBytes: 103, URIBytes: 104,
		PurposeBytes: 105, CredentialBytes: 106, RequestedTools: 107, ResourceEntries: 108,
	}
	if c.Limits != want {
		t.Errorf("Limits = %+v, want %+v", c.Limits, want)
	}

	for _, n := range names {
		for _, bad := range []string{"0", "-1", "big"} {
			t.Setenv(n, bad)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), n) {
				t.Errorf("%s=%q: Load() error = %v, want one naming it", n, bad, err)
			}
		}
		t.Setenv(n, "")
	}
}

func TestLoad_PrincipalOIDCKeyRefresh(t *testing.T) {
	setValidEnv(t)
	t.Setenv("STRATIUM_PRINCIPAL_OIDC_KEY_REFRESH_INTERVAL", "")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if c.PrincipalOIDCKeyRefresh != 30*time.Second {
		t.Errorf("default PrincipalOIDCKeyRefresh = %s, want 30s", c.PrincipalOIDCKeyRefresh)
	}

	t.Setenv("STRATIUM_PRINCIPAL_OIDC_KEY_REFRESH_INTERVAL", "2m")
	if c, err = Load(); err != nil || c.PrincipalOIDCKeyRefresh != 2*time.Minute {
		t.Errorf("Load() = %s, %v; want 2m, nil", c.PrincipalOIDCKeyRefresh, err)
	}

	for _, bad := range []string{"0s", "-1s", "often"} {
		t.Setenv("STRATIUM_PRINCIPAL_OIDC_KEY_REFRESH_INTERVAL", bad)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "STRATIUM_PRINCIPAL_OIDC_KEY_REFRESH_INTERVAL") {
			t.Errorf("value %q: Load() error = %v, want one naming the variable", bad, err)
		}
	}
}

func TestLoad_MaxPendingApprovals(t *testing.T) {
	setValidEnv(t)
	t.Setenv("STRATIUM_MAX_PENDING_APPROVALS", "")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if c.MaxPendingApprovals != 20 {
		t.Errorf("default MaxPendingApprovals = %d, want 20", c.MaxPendingApprovals)
	}

	t.Setenv("STRATIUM_MAX_PENDING_APPROVALS", "5")
	if c, err = Load(); err != nil || c.MaxPendingApprovals != 5 {
		t.Errorf("Load() = %d, %v; want 5, nil", c.MaxPendingApprovals, err)
	}

	for _, bad := range []string{"0", "-1", "lots"} {
		t.Setenv("STRATIUM_MAX_PENDING_APPROVALS", bad)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "STRATIUM_MAX_PENDING_APPROVALS") {
			t.Errorf("value %q: Load() error = %v, want one naming the variable", bad, err)
		}
	}
}
