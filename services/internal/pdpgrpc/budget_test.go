package pdpgrpc

import (
	"context"
	"errors"
	"strings"
	"sync"
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
		if ok, _ := b.take(context.Background(), a, now); !ok {
			t.Fatalf("call %d inside the burst was refused", i)
		}
	}
	if ok, _ := b.take(context.Background(), a, now); ok {
		t.Fatal("a call past the burst was allowed")
	}
	if ok, _ := b.take(context.Background(), other, now); !ok {
		t.Fatal("another session was refused because of this one")
	}
	if ok, _ := b.take(context.Background(), a, now.Add(time.Second)); !ok {
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
	b.take(context.Background(), id, now) // the burst

	if ok, report := b.take(context.Background(), id, now); ok || report != 1 {
		t.Fatalf("first refusal = (%v, %d), want (false, 1): reported at once", ok, report)
	}
	for range 5 {
		if ok, report := b.take(context.Background(), id, now); ok || report != 0 {
			t.Fatalf("a refusal inside the interval = (%v, %d), want (false, 0)", ok, report)
		}
	}
	later := now.Add(budgetAuditInterval)
	if ok, report := b.take(context.Background(), id, later); !ok || report != 5 {
		t.Fatalf("an allowed call after the interval = (%v, %d), want (true, 5)", ok, report)
	}
}

func TestSessionBudgets_ForgetsIdleSessions(t *testing.T) {
	b := sessionBudgets{perSecond: 1, burst: 2}
	now := time.Now()
	for range 50 {
		b.take(context.Background(), uuid.New(), now)
	}
	b.take(context.Background(), uuid.New(), now.Add(2*budgetSweepInterval))
	if n := len(b.sessions); n != 1 {
		t.Errorf("sessions remembered = %d, want 1: the idle ones were full again and had nothing to report", n)
	}
}

func TestSessionBudgets_ZeroValueHasNoBudget(t *testing.T) {
	var b sessionBudgets
	id, now := uuid.New(), time.Now()
	for i := range 100 {
		if ok, _ := b.take(context.Background(), id, now); !ok {
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

// sharedBucket stands in for the store every PDP shares: one token bucket for
// each session, with a clock the test moves.
type sharedBucket struct {
	mu       sync.Mutex
	now      time.Time
	tokens   map[uuid.UUID]float64
	touched  map[uuid.UUID]time.Time
	leases   int
	leaseErr error
}

func (s *sharedBucket) LeaseSessionTokens(_ context.Context, session uuid.UUID, burst, perSecond float64, want int) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.leases++
	if s.leaseErr != nil {
		return 0, s.leaseErr
	}
	if s.tokens == nil {
		s.tokens, s.touched = map[uuid.UUID]float64{}, map[uuid.UUID]time.Time{}
	}
	have, seen := s.tokens[session]
	if !seen {
		have = burst
	} else {
		have = min(burst, have+s.now.Sub(s.touched[session]).Seconds()*perSecond)
	}
	got := min(want, int(have))
	s.tokens[session], s.touched[session] = have-float64(got), s.now
	return got, nil
}

// Two PDPs that share a store allow one session its budget between them, not
// each: the point of sharing.
func TestSessionBudgets_Shared_TwoServersShareOneBudget(t *testing.T) {
	shared := &sharedBucket{now: time.Now()}
	a := sessionBudgets{perSecond: 2, burst: 6, shared: shared}
	b := sessionBudgets{perSecond: 2, burst: 6, shared: shared}
	session := uuid.New()

	allowed := 0
	for range 20 {
		for _, pdp := range []*sessionBudgets{&a, &b} {
			if ok, _ := pdp.take(context.Background(), session, shared.now); ok {
				allowed++
			}
		}
	}
	if allowed != 6 {
		t.Errorf("calls allowed across two PDPs = %d, want the one budget of 6", allowed)
	}

	// A second later two more tokens exist, whichever PDP is asked.
	shared.now = shared.now.Add(time.Second)
	allowed = 0
	for range 10 {
		for _, pdp := range []*sessionBudgets{&a, &b} {
			if ok, _ := pdp.take(context.Background(), session, shared.now); ok {
				allowed++
			}
		}
	}
	if allowed != 2 {
		t.Errorf("calls allowed a second later = %d, want 2", allowed)
	}
}

// Tokens come from the store in blocks, and a session that has run out is not
// asked about again until a token could exist: calls are far more numerous
// than store calls, allowed or refused.
func TestSessionBudgets_Shared_AsksTheStoreRarely(t *testing.T) {
	shared := &sharedBucket{now: time.Now()}
	b := sessionBudgets{perSecond: 20, burst: 100, shared: shared}
	session := uuid.New()

	for range 100 {
		if ok, _ := b.take(context.Background(), session, shared.now); !ok {
			t.Fatal("a call inside the burst was refused")
		}
	}
	if shared.leases != 5 {
		t.Errorf("store calls for 100 allowed calls = %d, want 5 (blocks of 20)", shared.leases)
	}
	for range 500 {
		if ok, _ := b.take(context.Background(), session, shared.now); ok {
			t.Fatal("a call past the burst was allowed")
		}
	}
	if shared.leases != 6 {
		t.Errorf("store calls after 500 refused calls = %d, want 6: one that found nothing, then none", shared.leases)
	}
}

// A store that cannot be asked does not fail a call. The PDP counts the
// session on its own meanwhile, asks the store again only after a pause, and
// goes back to it once it answers.
func TestSessionBudgets_Shared_StoreFailureFallsBackToCountingAlone(t *testing.T) {
	shared := &sharedBucket{now: time.Now(), leaseErr: errors.New("database is down")}
	b := sessionBudgets{perSecond: 0.001, burst: 3, shared: shared}
	session := uuid.New()
	now := shared.now

	allowed := 0
	for range 10 {
		if ok, _ := b.take(context.Background(), session, now); ok {
			allowed++
		}
	}
	if allowed != 3 {
		t.Errorf("calls allowed while the store is down = %d, want 3: still held to the burst, by this PDP alone", allowed)
	}
	if shared.leases != 1 {
		t.Errorf("store calls while it is down = %d, want 1: asked once, then left alone for the pause", shared.leases)
	}

	// The store is back, and the pause is over: the next call but one is
	// counted by the store again.
	shared.leaseErr = nil
	later := now.Add(leaseRetryInterval)
	shared.now = later
	b.take(context.Background(), session, later)
	before := shared.leases
	if ok, _ := b.take(context.Background(), session, later); !ok {
		t.Error("a call after the store came back was refused, want it allowed from the shared budget")
	}
	if shared.leases != before+1 {
		t.Errorf("store calls after it came back = %d more, want 1: the session is shared again", shared.leases-before)
	}
}

// Decide with the store down still decides.
func TestDecide_Shared_StoreFailureDoesNotFailTheCall(t *testing.T) {
	fs, req, _ := decideTokenFixture(t)
	shared := &sharedBucket{now: time.Now(), leaseErr: errors.New("database is down")}
	cfg := testConfig()
	cfg.SessionCallsPerSecond, cfg.SessionCallsBurst = 20, 100
	srv := NewServer(fs, denyAllPolicy(), cfg, &fakeSigner{}).WithSessionBudgetStore(shared)

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v, want a decision", err)
	}
	if resp.GetDeniedLeg() != "principal" {
		t.Errorf("DeniedLeg = %q (reason %q), want principal: the call must reach the policy", resp.GetDeniedLeg(), resp.GetReason())
	}
}

// An outage that lasts through several retries is one burst, not one at each.
func TestSessionBudgets_Shared_LongOutageIsNotAFreshBurstAtEveryRetry(t *testing.T) {
	shared := &sharedBucket{now: time.Now(), leaseErr: errors.New("database is down")}
	b := sessionBudgets{perSecond: 0.001, burst: 3, shared: shared}
	session := uuid.New()

	allowed := 0
	for retry := range 5 {
		now := shared.now.Add(time.Duration(retry) * leaseRetryInterval)
		for range 10 {
			if ok, _ := b.take(context.Background(), session, now); ok {
				allowed++
			}
		}
	}
	if allowed != 3 {
		t.Errorf("calls allowed across five retries of a store that stayed down = %d, want 3", allowed)
	}
}
