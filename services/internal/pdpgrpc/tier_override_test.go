// Tests for the override step of spec §4.4's resolution order reaching a
// real decision (Phase 14 Task 7 — .superpowers/sdd/2026-08-14-phase-14-pap/
// task-7-brief.md). authz.DeriveTier has consulted TierTable.Overrides since
// Phase 2; nothing ever populated that map outside internal/authz's own
// tests, so an operator could author an override, be correctly refused a
// lowering one, and have the accepted one reach nothing at all.
//
// Kept in one file, separate from server_test.go, for the same reason
// epoch_test.go is: this is one property with several halves (the override
// is loaded, honored when it raises, dropped and surfaced when it does not,
// and read after the epoch), and grouping by property reads better than
// scattering it through a file organized by RPC.
//
// Every test here goes through the real Decide, never honoredOverrides
// directly. "The change reaches a real decision" is the entire point of the
// task, and a unit test of the filter alone would have passed just as
// happily on the day the map was wired to nothing.
package pdpgrpc

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"stratium/pkg/models"
)

// captureLogs points slog's default logger at a buffer for the duration of
// one test and restores it afterwards. Safe here without further ceremony:
// slog.SetDefault stores through an atomic pointer, and no test in this
// package calls t.Parallel.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &buf
}

// TestDecide_OverrideRaisesTheDerivedTier is the task's headline property:
// an override raises a tool's tier and the change reaches a real decision.
//
// Both halves are asserted, and the second is what makes this more than a
// field check. `ls -la` on Bash derives READ_ONLY without an override, which
// sits under the fixture delegation's INTERNAL_MODIFY ceiling; the override
// takes it to DESTRUCTIVE, which does not — so the delegation leg flips from
// allowing to denying. A mutation that reported the raised tier on the wire
// without feeding it to authz.Decide would pass the first assertion and fail
// the second.
func TestDecide_OverrideRaisesTheDerivedTier(t *testing.T) {
	fs, req := wellFormedFixture()
	req.RawInput = "ls -la"
	fs.overrides = map[string]models.ActionTier{"Bash": models.ActionTierDestructive}
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if got := resp.GetDerivedTier(); got != int32(models.ActionTierDestructive) {
		t.Fatalf("DerivedTier = %d, want %d (DESTRUCTIVE): the tenant's override must win the resolution",
			got, models.ActionTierDestructive)
	}
	if resp.GetDelegationEffect() != Effect_EFFECT_DENY {
		t.Errorf("DelegationEffect = %v (%q), want DENY: the raised tier must reach the ceiling check, "+
			"not merely be reported — this same call derives READ_ONLY and allows without the override",
			resp.GetDelegationEffect(), resp.GetDelegationReason())
	}
}

// TestDecide_OverrideWithoutARowChangesNothing is the regression guard that
// makes turning this read on safe for every tenant that has never written an
// override — which was every tenant, since the table had no reader at all.
// fakeStore's zero-value overrides map (nil) is what store.LoadTierOverrides
// returns for such a tenant.
func TestDecide_OverrideWithoutARowChangesNothing(t *testing.T) {
	fs, req := wellFormedFixture()
	req.RawInput = "ls -la"
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if got := resp.GetDerivedTier(); got != int32(models.ActionTierReadOnly) {
		t.Errorf("DerivedTier = %d, want %d (READ_ONLY): a tenant with no override rows must derive "+
			"exactly as it did before this table had a reader", got, models.ActionTierReadOnly)
	}
}

// TestDecide_OverrideEqualToItsBaselineIsHonored is the read-time check's own
// boundary case. ValidateOverride refuses "override < baseline", so an
// override EQUAL to the baseline is honored, and an off-by-one mutation of <
// into <= drops a row it must keep.
//
// DerivedTier alone cannot prove this and asserting only on it would make the
// test structurally blind: honored, the override yields READ_ONLY; dropped,
// the baseline beneath it is also READ_ONLY. Identical by construction — that
// is what "equal" means here. The log line is the only observable difference
// between the two outcomes, so the empty-buffer assertion is what carries the
// property; the DerivedTier check below is a sanity check, not the point.
func TestDecide_OverrideEqualToItsBaselineIsHonored(t *testing.T) {
	logs := captureLogs(t)
	fs, req := wellFormedFixture()
	req.Tool = "Read"
	req.RawInput = "/tmp/notes.txt"
	fs.overrides = map[string]models.ActionTier{"Read": models.ActionTierReadOnly}
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if out := logs.String(); out != "" {
		t.Errorf("the override was dropped, not honored: %s\n"+
			"an override equal to its baseline is not a lowering — ValidateOverride refuses "+
			"\"override < baseline\", never \"override <= baseline\"", out)
	}
	if got := resp.GetDerivedTier(); got != int32(models.ActionTierReadOnly) {
		t.Errorf("DerivedTier = %d, want %d", got, models.ActionTierReadOnly)
	}
}

// TestDecide_OverrideBelowCatalogBaselineIsDropped is the read-time half of
// Task 7's correction, on the CATALOG baseline path. The tenant catalogs
// Bash as DESTRUCTIVE and a row in tier_overrides claims INTERNAL_MODIFY for
// it — a row that passes the schema's own tier_overrides_raise_only CHECK
// (which compares against a stored builtin_tier column a direct write
// supplies for itself) and passed the OLD write-time check too, since
// INTERNAL_MODIFY outranks Bash's built-in floor. Honoring it would lower
// the effective tier from DESTRUCTIVE to INTERNAL_MODIFY.
//
// Dropped, and the resolution falls through to the catalog entry beneath it
// — the higher tier, which is the safe direction and the reason dropping
// beats failing the decision.
func TestDecide_OverrideBelowCatalogBaselineIsDropped(t *testing.T) {
	fs, req := wellFormedFixture()
	req.RawInput = "ls -la"
	fs.catalog = []models.ToolCatalogEntry{{ToolName: "Bash", ActionTier: tierPtr(models.ActionTierDestructive)}}
	fs.overrides = map[string]models.ActionTier{"Bash": models.ActionTierInternalModify}
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if got := resp.GetDerivedTier(); got != int32(models.ActionTierDestructive) {
		t.Errorf("DerivedTier = %d, want %d (DESTRUCTIVE, the catalog entry beneath the dropped override): "+
			"an override below the tenant's own catalog entry is a lowering and must not be honored",
			got, models.ActionTierDestructive)
	}
}

// TestDecide_OverrideBelowBuiltinBaselineIsDropped is the same property on
// the OTHER baseline path — no catalog row at all, so the baseline is
// DefaultCatalog()'s own READ_ONLY for Read. Both paths are tested because
// they are different branches of OverrideBaseline: a mutation that dropped
// the catalog lookup would pass this test, and one that dropped the built-in
// fallback would pass the catalog test above.
func TestDecide_OverrideBelowBuiltinBaselineIsDropped(t *testing.T) {
	fs, req := wellFormedFixture()
	req.Tool = "Read"
	req.RawInput = "/tmp/notes.txt"
	fs.overrides = map[string]models.ActionTier{"Read": models.ActionTierReasoning}
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if got := resp.GetDerivedTier(); got != int32(models.ActionTierReadOnly) {
		t.Errorf("DerivedTier = %d, want %d (READ_ONLY, the built-in beneath the dropped override)",
			got, models.ActionTierReadOnly)
	}
}

// TestDecide_CompositeOverrideKeyCannotLowerItsTool covers the key shape
// neither baseline path above reaches. deriveTierByName consults
// "Tool:verb" BEFORE "Tool" (lookupKeys), and a tenant catalog row supplying
// a verb is what makes that composite key match a real request — so an
// override keyed "Read:read" wins ahead of the "Read" catalog entry it
// lowers. Measured against a naive per-key baseline it would be measured
// against the floor, clear the raise-only check at any tier at all, and
// lower Read to REASONING for every call.
func TestDecide_CompositeOverrideKeyCannotLowerItsTool(t *testing.T) {
	fs, req := wellFormedFixture()
	req.Tool = "Read"
	req.RawInput = "/tmp/notes.txt"
	fs.catalog = []models.ToolCatalogEntry{{
		ToolName: "Read", ActionTier: tierPtr(models.ActionTierReadOnly), Verb: "read",
	}}
	fs.overrides = map[string]models.ActionTier{"Read:read": models.ActionTierReasoning}
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if got := resp.GetDerivedTier(); got != int32(models.ActionTierReadOnly) {
		t.Errorf("DerivedTier = %d, want %d: a composite-key override must be measured against the same "+
			"resolution its key can win, or it lowers a tool by spelling its key longer",
			got, models.ActionTierReadOnly)
	}
}

// TestDecide_NullTierCatalogRowOverrideIsHonored is the ruling on the case
// the old store.builtinTier doc comment named as its one live reason for
// excluding the tenant catalog: a NULL-tier row (Bash-shaped — "no fixed
// tier, classify per command") has no static tier to compare an override
// against.
//
// The override is honored, not refused. The row contributes no entry to the
// merged catalog (BuildTierCatalog), so the key falls through to the
// built-in resolution, which for Bash is the floor — and raising Bash to
// DESTRUCTIVE tenant-wide is the most legitimate thing this table does.
//
// The residual, stated where it can be seen rather than only in a doc
// comment: `ls -la` would classify READ_ONLY per command, and this override
// replaces that with a flat DESTRUCTIVE. That is the tenant's own choice,
// and DeriveTier's evidence rule still binds above it in the direction that
// matters — evidence only ever RAISES.
func TestDecide_NullTierCatalogRowOverrideIsHonored(t *testing.T) {
	fs, req := wellFormedFixture()
	commandField := "command"
	req.RawInput = `{"command":"ls -la"}`
	fs.catalog = []models.ToolCatalogEntry{{ToolName: "Bash", ActionTier: nil, CommandField: &commandField}}
	fs.overrides = map[string]models.ActionTier{"Bash": models.ActionTierDestructive}
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if got := resp.GetDerivedTier(); got != int32(models.ActionTierDestructive) {
		t.Errorf("DerivedTier = %d, want %d: an override on a NULL-tier catalog entry must be honored, "+
			"not refused for having no static baseline", got, models.ActionTierDestructive)
	}
}

// TestDecide_DroppedOverrideIsSurfaced is the "never silently honored, and
// never silently dropped either" half. An operator whose override is being
// ignored has to be able to find out why, and a row that fails this check is
// either a configuration mistake or a write that bypassed the control plane.
//
// The assertions name the three things the line must carry — the key, the
// tier claimed, and the baseline it failed against — and one thing it must
// NOT: nothing identifying who wrote the row. The decision path does not even
// select tier_overrides.created_by (store.LoadTierOverrides), so there is
// nothing here to leak by accident; this asserts it anyway, because the
// cheapest place to catch a future "just add the operator, it would help
// debugging" is a test that says no.
func TestDecide_DroppedOverrideIsSurfaced(t *testing.T) {
	logs := captureLogs(t)
	fs, req := wellFormedFixture()
	req.Tool = "Read"
	req.RawInput = "/tmp/notes.txt"
	fs.overrides = map[string]models.ActionTier{"Read": models.ActionTierReasoning}
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	if _, err := srv.Decide(context.Background(), req); err != nil {
		t.Fatalf("Decide() error = %v", err)
	}

	out := logs.String()
	if out == "" {
		t.Fatal("nothing was logged: a dropped override must be surfaced, never silently discarded")
	}
	for _, want := range []string{"Read", models.ActionTierReasoning.String(), models.ActionTierReadOnly.String()} {
		if !strings.Contains(out, want) {
			t.Errorf("log output does not mention %q, which an operator needs to fix the row: %s", want, out)
		}
	}
	if strings.Contains(out, testTenant) {
		t.Errorf("log output names the tenant; this process serves exactly one and says so at startup: %s", out)
	}
}

// TestDecide_HonoredOverrideIsNotLogged is the other side of the line above:
// the ordinary case must be quiet. A per-decision log line for every override
// a tenant has legitimately configured would be noise on every single request
// — which is how a warning that matters stops being read.
func TestDecide_HonoredOverrideIsNotLogged(t *testing.T) {
	logs := captureLogs(t)
	fs, req := wellFormedFixture()
	req.RawInput = "ls -la"
	fs.overrides = map[string]models.ActionTier{"Bash": models.ActionTierDestructive}
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	if _, err := srv.Decide(context.Background(), req); err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if out := logs.String(); out != "" {
		t.Errorf("an honored override logged %q, want nothing", out)
	}
}

// TestDecide_TierOverrideLoadFailureDeniesAndAudits is the fail-closed
// requirement, and the argument differs from the catalog's own version
// (TestDecide_ToolCatalogLoadFailureDeniesAndAudits, server_test.go) even
// though the shape is identical: an override exists only to RAISE a tier, so
// proceeding as though the tenant had none would under-rate precisely the
// actions it took the trouble to mark as more sensitive.
func TestDecide_TierOverrideLoadFailureDeniesAndAudits(t *testing.T) {
	fs, req := wellFormedFixture()
	fs.overridesErr = errors.New("connection reset")
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v, want a decision (fail closed, not a bare RPC error)", err)
	}
	if resp.GetEffect() != Effect_EFFECT_DENY {
		t.Fatalf("Effect = %v, want EFFECT_DENY", resp.GetEffect())
	}
	if !strings.Contains(resp.GetReason(), "tier overrides") {
		t.Errorf("Reason = %q, want it to name the tier override load failure", resp.GetReason())
	}
	if len(fs.appended) != 1 {
		t.Errorf("audit entries appended = %d, want 1: a pre-decision denial is audited like any other", len(fs.appended))
	}
}

// TestDecide_EpochIsTheFirstStoreRead is spec §4.8.1 V3's ordering, asserted
// against the whole of Decide rather than against one other read. The epoch
// must be read before ANYTHING else this RPC loads, so a revocation racing
// the call can only make the response look older than the state it reflects.
//
// This exists because the pre-existing proof
// (TestDecide_EpochReflectsStateBeforeAConcurrentBump, epoch_test.go)
// observes ordering only through a hook inside LoadAgent: a read inserted
// ahead of the epoch but behind that hook — the tier override read this task
// adds, moved one step too early — would leave it passing. Overrides are set
// here so the new read is genuinely on the path being ordered, not skipped.
func TestDecide_EpochIsTheFirstStoreRead(t *testing.T) {
	fs, req := wellFormedFixture()
	fs.epoch = 55123
	fs.overrides = map[string]models.ActionTier{"Bash": models.ActionTierDestructive}
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	if _, err := srv.Decide(context.Background(), req); err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if fs.epochReadAfterCalls != 0 {
		t.Errorf("%d store reads ran before LoadTenantEpoch, want 0: the epoch is read FIRST so a decision "+
			"can only be labelled older than the state it reflects, never newer (V3)", fs.epochReadAfterCalls)
	}
}
