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
		`psql -c 'TRUNCATE audit_chain'`:                                models.ActionTierDestructive,
		`mysql -e 'DROP DATABASE prod'`:                                 models.ActionTierDestructive,
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

// Matching must consider the RAW string as well as the normalized one.
// Normalization strips quotes, which can merge two tokens and destroy a word
// boundary the raw form had: in `psql -c abc"DROP TABLE users"` the raw
// string matches \bDROP\b, but the normalized `psql -c abcDROP TABLE users`
// does not. Dropping the raw arm of the match therefore loses detections
// rather than gaining them, and nothing else in the suite catches that.
//
// The example needs a SQL-context tool (psql) in front of it now that DROP
// is scoped to reDestructiveSQL: the same bare "DROP TABLE" text with no SQL
// tool present is the prose collision this task removes, not a load-bearing
// detection — see TestBuiltinTier_SQLKeywordsNeedSQLContext.
func TestBuiltinTier_RawMatchIsLoadBearing(t *testing.T) {
	const cmd = `psql -c abc"DROP TABLE users"`
	got, ok := BuiltinTier(Action{Tool: "Bash", RawInput: cmd})
	if !ok || got < models.ActionTierDestructive {
		t.Fatalf("got %v (ok=%v); the raw-string match must still see DROP TABLE here", got, ok)
	}
	if normalizeCommand(cmd) == cmd {
		t.Fatal("test premise broken: normalization no longer alters this input")
	}
}

// SQL keywords outside a SQL context are ordinary English and must not
// escalate an unrelated command. Rating a commit message DESTRUCTIVE pushes
// operators to widen delegations, which weakens the system through friction.
func TestBuiltinTier_SQLKeywordsNeedSQLContext(t *testing.T) {
	prose := []string{
		`git commit -m "revoke stale session tokens"`,
		`git commit -m "we should alter table layout later"`,
		`echo "drop table talk is just prose here"`,
	}
	for _, cmd := range prose {
		t.Run(cmd, func(t *testing.T) {
			if got, _ := BuiltinTier(Action{Tool: "Bash", RawInput: cmd}); got >= models.ActionTierDestructive {
				t.Fatalf("prose containing a SQL keyword rated %v; no database is being touched", got)
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

// Claude Code sends tool_input as JSON. reReadOnly is anchored (^\s*(cat|
// ls|...)), so a JSON blob's leading token is never one of its command
// names, and classification falls through to the "unrecognized -> assumed
// modifying" default no matter what the underlying command actually does.
// Destructive detection is unaffected, because reDestructive is an
// unanchored substring match. This pins today's (pre-normalized_input)
// behavior as the baseline the composition tests below build on — see
// docs/superpowers/plans/2026-08-10-phase-3b-normalized-input.md.
func TestBuiltinTier_JSONRawInputAlone(t *testing.T) {
	cases := map[string]models.ActionTier{
		`{"command":"ls -la"}`:         models.ActionTierInternalModify,
		`{"command":"cat /etc/hosts"}`: models.ActionTierInternalModify,
		`{"file_path":"/tmp/x.txt"}`:   models.ActionTierInternalModify,
		`{"command":"rm -rf /"}`:       models.ActionTierDestructive, // unanchored: already correct
		"ls -la":                       models.ActionTierReadOnly,    // bare, what every other test assumed
	}
	for raw, want := range cases {
		t.Run(raw, func(t *testing.T) {
			got, ok := BuiltinTier(Action{Tool: "Bash", RawInput: raw})
			if !ok || got != want {
				t.Fatalf("raw %q: got %v (ok=%v), want %v", raw, got, ok, want)
			}
		})
	}
}

// A correct NormalizedInput extraction is evidence, and evidence beats a
// default. RawInput's own classification of an opaque JSON blob never
// positively matches a pattern — the anchored read-only regexp cannot match
// a `{`-leading string — so it falls through to classifyInput's
// "unrecognized -> assume it modifies" default. That default is absence of
// evidence, not a competing classification, so it must not outrank a
// NormalizedInput that positively matches READ_ONLY. Plain "take the more
// severe of the two" gets this wrong, because INTERNAL_MODIFY (the default)
// outranks READ_ONLY — that was the original defect this task fixes: every
// JSON-wrapped read stayed floored at tier 2 forever. The rm -rf / case is
// unaffected by any of this: RawInput's own unanchored destructive match
// already lands on DESTRUCTIVE without help from NormalizedInput.
func TestBuiltinTier_NormalizedInputComposesWithJSONRawInput(t *testing.T) {
	cases := []struct {
		raw, normalized string
		want            models.ActionTier
	}{
		{`{"command":"rm -rf /"}`, "rm -rf /", models.ActionTierDestructive},
		{`{"command":"ls -la"}`, "ls -la", models.ActionTierReadOnly},
		{`{"command":"cat /etc/hosts"}`, "cat /etc/hosts", models.ActionTierReadOnly},
	}
	for _, c := range cases {
		t.Run(c.raw, func(t *testing.T) {
			got, ok := BuiltinTier(Action{Tool: "Bash", RawInput: c.raw, NormalizedInput: c.normalized})
			if !ok || got != c.want {
				t.Fatalf("raw %q normalized %q: got %v (ok=%v), want %v", c.raw, c.normalized, got, ok, c.want)
			}
		})
	}
}

// A bare path is not a command, and the classifier has no pattern for one:
// RawInput's JSON wrapper falls through to the default (no positive match),
// and NormalizedInput's bare path ALSO falls through to the default (it
// matches none of reDestructive/reSQLContext/reExternal/reCompound/
// reReadOnly). With neither side offering positive evidence, step 2 does
// not apply — NormalizedInput did not "classify" in the sense that matters
// — so the result is RawInput's own default, INTERNAL_MODIFY, exactly as if
// NormalizedInput had been absent. Decision, stated explicitly rather than
// left to fall out silently: a bare path gets no special-cased tier here;
// inventing one (e.g. treating it as READ_ONLY because "it looks like a
// file" or suppressing raw's default) would be evidence the classifier
// never produced. A PEP that wants file reads to classify precisely should
// extract a command, not a path.
func TestBuiltinTier_BarePathNeitherInputMatchesAPattern(t *testing.T) {
	got, ok := BuiltinTier(Action{
		Tool:            "Bash",
		RawInput:        `{"file_path":"/tmp/x"}`,
		NormalizedInput: "/tmp/x",
	})
	if !ok || got != models.ActionTierInternalModify {
		t.Fatalf("got %v (ok=%v), want INTERNAL_MODIFY: neither input positively matches a pattern, "+
			"so the result falls through to raw's own default", got, ok)
	}
}

// This is the property that makes the design safe against a buggy or
// hostile PEP: an extraction that under-reports must not lower the tier
// below what raw_input alone would produce. raw_input is still scanned by
// the unanchored destructive patterns regardless of what normalized_input
// claims. If this test does not hold, a PEP can hide "rm -rf /" behind a
// normalized_input of "ls".
func TestBuiltinTier_NormalizedInputCannotLowerTier(t *testing.T) {
	got, ok := BuiltinTier(Action{
		Tool:            "Bash",
		RawInput:        `{"command":"rm -rf /"}`,
		NormalizedInput: "ls",
	})
	if !ok || got != models.ActionTierDestructive {
		t.Fatalf("under-reporting normalized_input lowered the tier: got %v (ok=%v), want DESTRUCTIVE", got, ok)
	}
}

// "More severe wins" must hold in both directions: a normalized_input that
// reveals something worse than raw_input alone would suggest must also
// raise the tier, not just fail to lower it.
func TestBuiltinTier_NormalizedInputMoreSevereThanRawWins(t *testing.T) {
	got, ok := BuiltinTier(Action{
		Tool:            "Bash",
		RawInput:        "ls",
		NormalizedInput: "rm -rf /",
	})
	if !ok || got != models.ActionTierDestructive {
		t.Fatalf("got %v (ok=%v), want DESTRUCTIVE: a more severe normalized_input must win", got, ok)
	}
}

// An empty normalized_input — proto3's zero value, sent by a caller that
// never populated it, or one with nothing to add — must change nothing:
// BuiltinTier must fall back to RawInput's classification exactly as it did
// before this field existed.
func TestBuiltinTier_EmptyNormalizedInputChangesNothing(t *testing.T) {
	cases := []struct {
		name string
		a    Action
		want models.ActionTier
	}{
		{"destructive raw unaffected", Action{Tool: "Bash", RawInput: `{"command":"rm -rf /"}`, NormalizedInput: ""}, models.ActionTierDestructive},
		{"read-only raw unaffected", Action{Tool: "Bash", RawInput: "ls -la", NormalizedInput: ""}, models.ActionTierReadOnly},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := BuiltinTier(c.a)
			if !ok || got != c.want {
				t.Fatalf("got %v (ok=%v), want %v", got, ok, c.want)
			}
		})
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
