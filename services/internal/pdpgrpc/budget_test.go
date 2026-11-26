package pdpgrpc

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestSessionBudgets_BurstThenRefill_PerSession(t *testing.T) {
	b := sessionBudgets{perSecond: 2, burst: 3}
	a, other := uuid.New(), uuid.New()
	now := time.Now()

	for i := range 3 {
		if ok, _ := b.take(a, now); !ok {
			t.Fatalf("call %d inside the burst was refused", i)
		}
	}
	if ok, _ := b.take(a, now); ok {
		t.Fatal("a call past the burst was allowed")
	}
	if ok, _ := b.take(other, now); !ok {
		t.Fatal("another session was refused because of this one")
	}
	if ok, _ := b.take(a, now.Add(time.Second)); !ok {
		t.Fatal("a call after a second's refill was refused")
	}
}

// Refusals are reported at most once per budgetAuditInterval, each report
// carrying the count since the one before, and the last of them is reported
// by a later allowed call so none goes unrecorded.
func TestSessionBudgets_ReportsRefusalsAtMostOncePerInterval(t *testing.T) {
	b := sessionBudgets{perSecond: 1, burst: 1}
	id := uuid.New()
	now := time.Now()
	b.take(id, now) // the burst

	if ok, report := b.take(id, now); ok || report != 1 {
		t.Fatalf("first refusal = (%v, %d), want (false, 1): reported at once", ok, report)
	}
	for range 5 {
		if ok, report := b.take(id, now); ok || report != 0 {
			t.Fatalf("a refusal inside the interval = (%v, %d), want (false, 0)", ok, report)
		}
	}
	later := now.Add(budgetAuditInterval)
	if ok, report := b.take(id, later); !ok || report != 5 {
		t.Fatalf("an allowed call after the interval = (%v, %d), want (true, 5)", ok, report)
	}
}

func TestSessionBudgets_ForgetsIdleSessions(t *testing.T) {
	b := sessionBudgets{perSecond: 1, burst: 2}
	now := time.Now()
	for range 50 {
		b.take(uuid.New(), now)
	}
	b.take(uuid.New(), now.Add(2*budgetSweepInterval))
	if n := len(b.sessions); n != 1 {
		t.Errorf("sessions remembered = %d, want 1: the idle ones were full again and had nothing to report", n)
	}
}

func TestSessionBudgets_ZeroValueHasNoBudget(t *testing.T) {
	var b sessionBudgets
	id, now := uuid.New(), time.Now()
	for i := range 100 {
		if ok, _ := b.take(id, now); !ok {
			t.Fatalf("call %d on a zero budget was refused", i)
		}
	}
}

// budgetConfig is testConfig with a budget of two calls and no refill worth
// the name, so the third call of a test is over it.
func budgetServer(fs *fakeStore) *Server {
	cfg := testConfig()
	cfg.SessionCallsPerSecond, cfg.SessionCallsBurst = 0.001, 2
	return NewServer(fs, denyAllPolicy(), cfg, &fakeSigner{})
}

// Decide over the budget is a DENY that says why, reads nothing from the
// store, and leaves one audit entry about the refusals, not one per call.
func TestDecide_OverTheSessionBudget_DeniesWithoutStoreWork(t *testing.T) {
	fs, req, delegationID := decideTokenFixture(t)
	srv := budgetServer(fs)
	for range 2 {
		if _, err := srv.Decide(context.Background(), req); err != nil {
			t.Fatalf("Decide() inside the budget: %v", err)
		}
	}
	callsBefore, rowsBefore := fs.calls, len(fs.appended)

	for range 10 {
		resp, err := srv.Decide(context.Background(), req)
		if err != nil {
			t.Fatalf("Decide() over the budget: error = %v, want a DENY decision", err)
		}
		if resp.GetEffect() != Effect_EFFECT_DENY || !strings.Contains(resp.GetReason(), "faster than the PDP allows") {
			t.Fatalf("Effect = %v, Reason = %q; want a DENY naming the budget", resp.GetEffect(), resp.GetReason())
		}
	}
	if got := fs.calls - callsBefore; got != 1 {
		t.Errorf("store calls for 10 refused calls = %d, want 1: the one audit entry", got)
	}
	rows := fs.appended[rowsBefore:]
	if len(rows) != 1 || rows[0].EventType != eventTypeCallBudgetExceeded {
		t.Fatalf("audit entries for 10 refused calls = %d, want one %s entry", len(rows), eventTypeCallBudgetExceeded)
	}
	if rows[0].DelegationID == nil || *rows[0].DelegationID != delegationID || !strings.Contains(rows[0].Reason, "1 calls refused") {
		t.Errorf("entry = delegation %v, reason %q; want this delegation and the count so far", rows[0].DelegationID, rows[0].Reason)
	}
}

func TestReportToolUse_OverTheSessionBudget_ResourceExhausted(t *testing.T) {
	fs, _, delegationID := decideTokenFixture(t)
	srv := budgetServer(fs)
	req := &ReportToolUseRequest{Token: delegationID.String(), Tool: "Bash", RawInput: "{}"}
	for range 2 {
		if _, err := srv.ReportToolUse(context.Background(), req); err != nil {
			t.Fatalf("ReportToolUse() inside the budget: %v", err)
		}
	}
	if _, err := srv.ReportToolUse(context.Background(), req); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("ReportToolUse() over the budget: error = %v, want ResourceExhausted", err)
	}
}

// A token carries its session, so calls under a child delegation count
// against the same budget as calls under its root.
func TestSessionOfToken_IsTheRootClaim_OrTheDelegationWithoutOne(t *testing.T) {
	signer := testSigner(t)
	srv := NewServer(&fakeStore{}, denyAllPolicy(), testConfig(), signer)
	child, root := uuid.New(), uuid.New()
	now := time.Now()

	tok, _, _, err := srv.mintToken(child, root, testTenant, "", now, now.Add(time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("mintToken: %v", err)
	}
	gotDelegation, _, gotSession, err := srv.authenticateToken(tok)
	if err != nil || gotDelegation != child || gotSession != root {
		t.Fatalf("authenticateToken() = %s, session %s, %v; want %s, session %s", gotDelegation, gotSession, err, child, root)
	}

	// A token from before the claim existed: its delegation is its session.
	old := signRealToken(t, signer, child, now, now.Add(time.Hour))
	if _, _, gotSession, err = srv.authenticateToken(old); err != nil || gotSession != child {
		t.Fatalf("a token with no root claim: session = %s, %v; want the delegation %s", gotSession, err, child)
	}
}

// A key-bound token presented without its proof spends nothing: only the
// holder of the key can draw on the session's budget. Otherwise a copied
// token, useless on its own, could still be used to lock its owner out.
func TestDecide_BoundTokenWithoutItsProof_SpendsNoBudget(t *testing.T) {
	f := newBoundFixture(t)
	f.srv.budgets = sessionBudgets{perSecond: 0.001, burst: 1}
	good := f.req.GetDpopProof()

	f.req.DpopProof = ""
	for range 5 {
		resp := f.decide(t)
		if resp.GetEffect() != Effect_EFFECT_DENY || strings.Contains(resp.GetReason(), "faster than the PDP allows") {
			t.Fatalf("without a proof: Effect = %v, Reason = %q; want a DENY about the proof", resp.GetEffect(), resp.GetReason())
		}
	}
	if n := len(f.srv.budgets.sessions); n != 0 {
		t.Errorf("sessions charged = %d, want 0", n)
	}

	f.req.DpopProof = good
	if resp := f.decide(t); resp.GetEffect() != Effect_EFFECT_ALLOW {
		t.Fatalf("the key holder's call after them: Effect = %v, Reason = %q; want ALLOW", resp.GetEffect(), resp.GetReason())
	}
}

// ReportToolUse refuses a key-bound token outright, so it must do that before
// counting the call.
func TestReportToolUse_BoundToken_IsRefusedWithoutSpendingBudget(t *testing.T) {
	f := newBoundFixture(t)
	f.srv.budgets = sessionBudgets{perSecond: 0.001, burst: 1}
	req := &ReportToolUseRequest{Token: f.req.GetToken(), Tool: "Bash", RawInput: "{}"}
	for range 5 {
		if _, err := f.srv.ReportToolUse(context.Background(), req); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("ReportToolUse() with a bound token: error = %v, want PermissionDenied", err)
		}
	}
	if n := len(f.srv.budgets.sessions); n != 0 {
		t.Errorf("sessions charged = %d, want 0", n)
	}
}

// ReportToolUse counts the call before it reads anything, so a caller over
// its budget costs no store work.
func TestReportToolUse_OverTheSessionBudget_ReadsNothing(t *testing.T) {
	fs, _, delegationID := decideTokenFixture(t)
	srv := budgetServer(fs)
	req := &ReportToolUseRequest{Token: delegationID.String(), Tool: "Bash", RawInput: "{}"}
	for range 2 {
		_, _ = srv.ReportToolUse(context.Background(), req)
	}
	// The first refusal writes the one audit entry about refusals; after it,
	// nothing.
	_, _ = srv.ReportToolUse(context.Background(), req)
	before := fs.calls
	for range 5 {
		if _, err := srv.ReportToolUse(context.Background(), req); status.Code(err) != codes.ResourceExhausted {
			t.Fatalf("over the budget: error = %v, want ResourceExhausted", err)
		}
	}
	if got := fs.calls - before; got != 0 {
		t.Errorf("store calls for 5 refused reports = %d, want 0", got)
	}
}
