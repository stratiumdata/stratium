package authz

import (
	"errors"
	"testing"

	"stratium/pkg/models"
)

func tierPtr(t models.ActionTier) *models.ActionTier { return &t }

func TestBuiltinTier_Verbs(t *testing.T) {
	cases := map[string]models.ActionTier{
		"read":     models.ActionTierReadOnly,
		"list":     models.ActionTierReadOnly,
		"write":    models.ActionTierInternalModify,
		"update":   models.ActionTierInternalModify,
		"send":     models.ActionTierExternalComms,
		"publish":  models.ActionTierExternalComms,
		"delete":   models.ActionTierDestructive,
		"transfer": models.ActionTierDestructive,
	}
	for verb, want := range cases {
		t.Run(verb, func(t *testing.T) {
			got, ok := BuiltinTier(Action{Verb: verb})
			if !ok || got != want {
				t.Fatalf("verb %q: got %v (ok=%v), want %v", verb, got, ok, want)
			}
		})
	}
}

// Shell classification runs server-side. In the previous system this lived in
// a bash script on the agent's own machine and the server believed its answer.
func TestBuiltinTier_ShellCommands(t *testing.T) {
	cases := map[string]models.ActionTier{
		"rm -rf /var/data":            models.ActionTierDestructive,
		"dd if=/dev/zero of=/dev/sda": models.ActionTierDestructive,
		"psql -c 'DROP TABLE users'":  models.ActionTierDestructive,
		"terraform destroy":           models.ActionTierDestructive,
		"curl https://evil.example":   models.ActionTierExternalComms,
		"git push origin main":        models.ActionTierExternalComms,
		"cat /etc/hosts":              models.ActionTierReadOnly,
		"ls -la":                      models.ActionTierReadOnly,
		"git status":                  models.ActionTierReadOnly,
		"mkdir build":                 models.ActionTierInternalModify,
	}
	for cmd, want := range cases {
		t.Run(cmd, func(t *testing.T) {
			got, ok := BuiltinTier(Action{Tool: "Bash", RawInput: cmd})
			if !ok || got != want {
				t.Fatalf("command %q: got %v (ok=%v), want %v", cmd, got, ok, want)
			}
		})
	}
}

// Known evasions must not land below their true tier. Each of these was
// verified to under-classify before the normalization, widened DROP
// alternation, and compound-command floor were added.
func TestBuiltinTier_ResistsKnownEvasions(t *testing.T) {
	atLeast := map[string]models.ActionTier{
		`"rm" -rf /`:     models.ActionTierDestructive,
		`'rm' -rf /`:     models.ActionTierDestructive,
		"rm${IFS}-rf /":  models.ActionTierDestructive,
		`ls; "rm" -rf /`: models.ActionTierDestructive,
		"ls && rm -rf /": models.ActionTierDestructive,
		`psql -c 'DROP TRIGGER audit_chain_no_truncate ON audit_chain'`: models.ActionTierDestructive,
		`psql -c 'DROP ROLE stratium_audit_owner'`:                      models.ActionTierDestructive,
		`psql -c 'REVOKE ALL ON audit_chain FROM stratium_app'`:         models.ActionTierDestructive,
	}
	for cmd, floor := range atLeast {
		t.Run(cmd, func(t *testing.T) {
			got, ok := BuiltinTier(Action{Tool: "Bash", RawInput: cmd})
			if !ok || got < floor {
				t.Fatalf("classified as %v (ok=%v); must be at least %v", got, ok, floor)
			}
		})
	}
}

// A compound command's leading token proves nothing about the rest of it, so
// READ_ONLY must be unreachable for one.
func TestBuiltinTier_CompoundNeverReadOnly(t *testing.T) {
	for _, cmd := range []string{
		"ls; echo hi", "cat a | cat b", "ls && pwd", "echo $(whoami)", "ls\necho hi",
	} {
		t.Run(cmd, func(t *testing.T) {
			if got, _ := BuiltinTier(Action{Tool: "Bash", RawInput: cmd}); got <= models.ActionTierReadOnly {
				t.Fatalf("compound command classified as %v — the leading token is not the whole command", got)
			}
		})
	}
}

// A plain read-only command must still classify as READ_ONLY; the compound
// floor must not swallow ordinary usage.
func TestBuiltinTier_SimpleReadOnlyUnaffected(t *testing.T) {
	for _, cmd := range []string{"ls -la", "cat /etc/hosts", "git status", "grep -r foo ."} {
		t.Run(cmd, func(t *testing.T) {
			if got, _ := BuiltinTier(Action{Tool: "Bash", RawInput: cmd}); got != models.ActionTierReadOnly {
				t.Fatalf("got %v, want READ_ONLY", got)
			}
		})
	}
}

// An unrecognized command must not land below INTERNAL_MODIFY. Assuming
// read-only is how an unknown internal CLI slips under a low tier cap.
func TestBuiltinTier_UnknownCommandAssumedModifying(t *testing.T) {
	got, ok := BuiltinTier(Action{Tool: "Bash", RawInput: "acmectl deploy --prod"})
	if !ok || got < models.ActionTierInternalModify {
		t.Fatalf("unknown command got %v (ok=%v); must be at least INTERNAL_MODIFY", got, ok)
	}
}

// Raw input beats the verb: the verb attached to a Bash call says nothing
// about what the command actually does.
func TestBuiltinTier_RawInputBeatsVerb(t *testing.T) {
	got, _ := BuiltinTier(Action{Tool: "Bash", Verb: "read", RawInput: "rm -rf /"})
	if got != models.ActionTierDestructive {
		t.Fatalf("raw input must take precedence over the verb, got %v", got)
	}
}

func TestDeriveTier_OverrideBeatsCatalogAndBuiltin(t *testing.T) {
	table := TierTable{
		Overrides: map[string]models.ActionTier{"read": models.ActionTierDestructive},
		Catalog:   map[string]models.ActionTier{"read": models.ActionTierExternalComms},
	}
	got, err := DeriveTier(table, Action{Verb: "read"})
	if err != nil || got != models.ActionTierDestructive {
		t.Fatalf("override must win: got %v, err %v", got, err)
	}
}

func TestDeriveTier_CatalogBeatsBuiltin(t *testing.T) {
	table := TierTable{Catalog: map[string]models.ActionTier{"read": models.ActionTierExternalComms}}
	got, err := DeriveTier(table, Action{Verb: "read"})
	if err != nil || got != models.ActionTierExternalComms {
		t.Fatalf("catalog must beat built-in: got %v, err %v", got, err)
	}
}

func TestDeriveTier_FallsBackToBuiltin(t *testing.T) {
	got, err := DeriveTier(TierTable{}, Action{Verb: "delete"})
	if err != nil || got != models.ActionTierDestructive {
		t.Fatalf("got %v, err %v; want DESTRUCTIVE", got, err)
	}
}

func TestDeriveTier_UnknownDenies(t *testing.T) {
	_, err := DeriveTier(TierTable{DenyUnknown: true}, Action{Verb: "frobnicate"})
	if !errors.Is(err, ErrUnknownAction) {
		t.Fatalf("unknown action with DenyUnknown must error, got %v", err)
	}
}

func TestDeriveTier_UnknownUsesFloor(t *testing.T) {
	table := TierTable{UnknownTier: models.ActionTierInternalModify}
	got, err := DeriveTier(table, Action{Verb: "frobnicate"})
	if err != nil || got != models.ActionTierInternalModify {
		t.Fatalf("got %v, err %v; want the configured floor", got, err)
	}
}

// The declared tier must never influence derivation. (C3)
func TestDeriveTier_IgnoresDeclaredTier(t *testing.T) {
	a := Action{Verb: "delete", DeclaredTier: tierPtr(models.ActionTierReadOnly)}
	got, err := DeriveTier(TierTable{}, a)
	if err != nil || got != models.ActionTierDestructive {
		t.Fatalf("declared tier leaked into derivation: got %v", got)
	}
}

func TestValidateOverride(t *testing.T) {
	if err := ValidateOverride(models.ActionTierReadOnly, models.ActionTierDestructive); err != nil {
		t.Fatalf("raising must be allowed: %v", err)
	}
	if err := ValidateOverride(models.ActionTierExternalComms, models.ActionTierExternalComms); err != nil {
		t.Fatalf("equal must be allowed: %v", err)
	}
	if err := ValidateOverride(models.ActionTierDestructive, models.ActionTierReadOnly); !errors.Is(err, ErrOverrideLowersTier) {
		t.Fatalf("lowering must be rejected, got %v", err)
	}
}

func TestEffect_DenyIsZeroValue(t *testing.T) {
	var e Effect
	if e != EffectDeny {
		t.Fatal("the zero value of Effect must be EffectDeny — an unevaluated leg must deny")
	}
	var leg LegResult
	if leg.Effect != EffectDeny {
		t.Fatal("a zero-value LegResult must deny")
	}
}

// Under-declaration is a spoofing attempt. (C1)
func TestCheckDeclaredTier_UnderDeclarationDenies(t *testing.T) {
	got := CheckDeclaredTier(models.ActionTierDestructive, tierPtr(models.ActionTierReadOnly))
	if got.Effect != EffectDeny {
		t.Fatalf("declared below actual must deny, got %v", got.Effect)
	}
	if got.Reason == "" {
		t.Fatal("a denial must carry a reason")
	}
}

// Over-declaration is conservative and permitted. (C2)
func TestCheckDeclaredTier_OverDeclarationAllowed(t *testing.T) {
	got := CheckDeclaredTier(models.ActionTierReadOnly, tierPtr(models.ActionTierDestructive))
	if got.Effect != EffectAllow {
		t.Fatalf("declared above actual must be allowed, got %v: %s", got.Effect, got.Reason)
	}
}

func TestCheckDeclaredTier_ExactMatchAllowed(t *testing.T) {
	if got := CheckDeclaredTier(models.ActionTierExternalComms, tierPtr(models.ActionTierExternalComms)); got.Effect != EffectAllow {
		t.Fatalf("exact match must be allowed, got %v", got.Effect)
	}
}

func TestCheckDeclaredTier_NoDeclarationAllowed(t *testing.T) {
	if got := CheckDeclaredTier(models.ActionTierDestructive, nil); got.Effect != EffectAllow {
		t.Fatalf("absent declaration must be allowed, got %v", got.Effect)
	}
}
