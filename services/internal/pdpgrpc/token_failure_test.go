package pdpgrpc

import (
	"context"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestFailureBudget_BurstThenRefill(t *testing.T) {
	b := failureBudget{perSecond: 5, burst: 20}
	now := time.Now()
	for i := range 20 {
		if ok, skipped := b.take(now); !ok || skipped != 0 {
			t.Fatalf("take %d = (%v, %d), want (true, 0): inside the burst", i, ok, skipped)
		}
	}
	for range 3 {
		if ok, _ := b.take(now); ok {
			t.Fatal("take past the burst = true, want false")
		}
	}
	// One second refills five rows; the first reports
	// what went unrecorded, and reports it once.
	later := now.Add(time.Second)
	if ok, skipped := b.take(later); !ok || skipped != 3 {
		t.Fatalf("take after refill = (%v, %d), want (true, 3)", ok, skipped)
	}
	if ok, skipped := b.take(later); !ok || skipped != 0 {
		t.Fatalf("second take after refill = (%v, %d), want (true, 0)", ok, skipped)
	}
}

func TestClipUnauthenticated(t *testing.T) {
	if got := clipCallerText("Bash"); got != "Bash" {
		t.Errorf("short value = %q, want it unchanged", got)
	}
	// Multi-byte runes, so a cut at a fixed byte count lands inside one.
	got := clipCallerText(strings.Repeat("é", maxAuditedCallerTextBytes))
	if len(got) > maxAuditedCallerTextBytes+len(clippedSuffix) {
		t.Errorf("len = %d, want at most %d", len(got), maxAuditedCallerTextBytes+len(clippedSuffix))
	}
	if !utf8.ValidString(got) {
		t.Error("clipped value is not valid UTF-8; Postgres would refuse the row")
	}
	if !strings.HasSuffix(got, clippedSuffix) {
		t.Errorf("clipped value %q does not say it was clipped", got[len(got)-20:])
	}
}

// A flood of calls with a token that does not authenticate is denied every
// time and writes a bounded number of audit rows.
func TestDecide_TokenFailures_AuditRowsAreCapped(t *testing.T) {
	fs, req := wellFormedFixture()
	req.Token = "not-a-token-at-all"
	srv := NewServer(fs, denyAllPolicy(), testConfig(), testSigner(t))

	const burst = 20
	const calls = burst + 30
	for i := range calls {
		resp, err := srv.Decide(context.Background(), req)
		if err != nil {
			t.Fatalf("call %d: Decide() error = %v, want a DENY decision", i, err)
		}
		if resp.GetEffect() != Effect_EFFECT_DENY {
			t.Fatalf("call %d: Effect = %v, want EFFECT_DENY", i, resp.GetEffect())
		}
	}
	if n := len(fs.appended); n < burst || n >= calls {
		t.Fatalf("audit rows = %d for %d calls, want at least the burst of %d and fewer than the calls",
			n, calls, burst)
	}
}

// The next row written says how many failures went unrecorded before it, and
// records the caller's text clipped.
func TestDecide_TokenFailure_RowCountsWhatWasSkippedAndClipsCallerText(t *testing.T) {
	fs, req := wellFormedFixture()
	req.Token = ""
	req.Tool = strings.Repeat("t", 10*maxAuditedCallerTextBytes)
	req.Subject = strings.Repeat("s", 10*maxAuditedCallerTextBytes)
	srv := NewServer(fs, denyAllPolicy(), testConfig(), testSigner(t))
	srv.failedTokens.tokens, srv.failedTokens.last, srv.failedTokens.skipped = 1, time.Now(), 7

	if _, err := srv.Decide(context.Background(), req); err != nil {
		t.Fatalf("Decide() error = %v, want a DENY decision", err)
	}
	if len(fs.appended) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(fs.appended))
	}
	row := fs.appended[0]
	if !strings.Contains(row.Reason, errNoToken.Error()) || !strings.Contains(row.Reason, "7 earlier") {
		t.Errorf("Reason = %q, want the token failure and the 7 unrecorded ones", row.Reason)
	}
	limit := maxAuditedCallerTextBytes + len(clippedSuffix)
	if len(row.ToolName) > limit || len(row.Actor) > limit {
		t.Errorf("ToolName is %d bytes and Actor %d, want at most %d each", len(row.ToolName), len(row.Actor), limit)
	}
}

// A Config built by hand, as the integration tests build theirs, has no cap:
// it must audit every failure, not none.
func TestFailureBudget_ZeroValueHasNoCap(t *testing.T) {
	var b failureBudget
	now := time.Now()
	for i := range 100 {
		if ok, _ := b.take(now); !ok {
			t.Fatalf("take %d on a zero budget = false, want true", i)
		}
	}
}
