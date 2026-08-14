// Tests for the tenant epoch's own wire plumbing (spec §4.8.1 V3; Phase 12
// Task 2 — .superpowers/sdd/2026-08-14-phase-12-revocation-epoch/
// task-2-brief.md): Decide, CreateDelegation, and IssueToken all read it via
// the single shared loadEpochOrDeny (server.go) and each attach it to their
// own response. Kept in one file, separate from server_test.go/
// delegation_test.go/token_test.go, because this is one property (read
// first, fail closed, attach to the response) proven identically across
// three RPCs — grouping by property reads better here than splitting the
// same argument three ways across files already organized by RPC.
//
// Every epoch value below is chosen to be far from 0 (a fakeStore field's
// Go zero value), 1 (store.defaultTenantEpoch, what an unseen tenant's
// LoadTenantEpoch reports), and 2 (migrations/000015_tenant_epoch_trigger's
// own first-bump value) — and far enough from each other within a single
// test — that a mixed-up fixture (the wrong field read, a swapped
// before/after) could not pass by coincidence.
package pdpgrpc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
)

// --- Decide ---

// TestDecide_EpochRoundTripsIntoResponse proves the ordinary case — the
// value LoadTenantEpoch reports reaches the response — and, with a second
// call against a different fs.epoch, that it is read fresh every time
// rather than cached anywhere on Server. A cache (a plausible-looking "it
// rarely changes" shortcut) or a hardcoded response value would both
// collapse the two calls to the same answer; two distinct, deliberately
// unrelated values is what makes that collapse visible.
func TestDecide_EpochRoundTripsIntoResponse(t *testing.T) {
	fs, req := wellFormedFixture()
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	fs.epoch = 48291
	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if resp.Epoch == nil {
		t.Fatal("response Epoch is unset, want present")
	}
	if got := resp.GetEpoch(); got != 48291 {
		t.Errorf("response epoch = %d, want %d", got, 48291)
	}

	fs.epoch = 60215
	resp2, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("second Decide() error = %v", err)
	}
	if got := resp2.GetEpoch(); got != 60215 {
		t.Errorf("second response epoch = %d, want %d — the epoch must be read fresh on every call, "+
			"never cached or hardcoded", got, 60215)
	}
}

// TestDecide_EpochReflectsStateBeforeAConcurrentBump is V3's own required
// proof: read the epoch first, before any other read, so a revocation
// racing this call can only make the response look OLDER than the state it
// actually reflects, never newer. This is the property the task brief calls
// "the one that matters," and it explicitly rules out proving it by
// inspection (reading the source and confirming the call comes first) — the
// requirement is a test that forces a bump to actually land between the
// epoch read and the next read, and checks what the response says.
//
// This forces that interleaving with a hook, not a goroutine racing a real
// database: fs.bumpOnAgentLoad fires synchronously inside LoadAgent, the
// read Decide performs immediately after loadEpochOrDeny succeeds
// (server.go's own comment at that call site) — the earliest point at which
// a concurrent bump's effects COULD be observed by anything Decide does
// next. Mutating fs.epoch there reproduces
//
//	read epoch (= before) -> [a bump lands here] -> read agent/chain/policies
//
// on every single run, deterministically. A real trigger racing a real
// Decide call over a real database would prove the same property, but only
// probabilistically — the bump would have to land inside a window measured
// in microseconds, and whether it does is a function of scheduling, not of
// whether Decide's ordering is correct, which is exactly the kind of flake
// a hook avoids by making the interleaving unconditional instead of timed.
//
// If Decide read the epoch anywhere at or after this hook — including the
// required "read it last" mutation — the response would carry `after`
// instead, and this test would fail.
func TestDecide_EpochReflectsStateBeforeAConcurrentBump(t *testing.T) {
	fs, req := wellFormedFixture()
	const before, after int64 = 30303, 71717
	fs.epoch = before
	fs.bumpOnAgentLoad = func() { fs.epoch = after }
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if resp.Epoch == nil {
		t.Fatal("response Epoch is unset, want present")
	}
	if got := resp.GetEpoch(); got != before {
		t.Errorf("response epoch = %d, want %d (read BEFORE the simulated concurrent bump to %d): "+
			"a decision must never be labelled with an epoch newer than the state it actually reflects",
			got, before, after)
	}
}

// TestDecide_EpochReadFailure_DeniesNotADefault is the fail-closed
// requirement: LoadTenantEpoch failing must deny outright, never substitute
// zero (or any other value) and continue. Unlike a tool catalog or
// DeriveTier failure (TestDecide_ToolCatalogLoadFailureDeniesAndAudits,
// server_test.go), this is a bare RPC error with no DecideResponse at all —
// the same shape LoadAgent/LoadChain failures already take — so there is no
// response for a default epoch to even appear on, which is the point:
// nothing here CAN report a fallback, because nothing here reaches the code
// that attaches one.
func TestDecide_EpochReadFailure_DeniesNotADefault(t *testing.T) {
	fs, req := wellFormedFixture()
	fs.epochErr = errors.New("connection reset")
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	resp, err := srv.Decide(context.Background(), req)
	if resp != nil {
		t.Fatalf("Decide() response = %+v, want nil: a read failure must never produce a response, "+
			"which is what rules out one silently carrying a default or zero epoch", resp)
	}
	wantCode(t, err, codes.Internal)
	if len(fs.appended) != 0 {
		t.Errorf("audit entries appended = %d, want 0: an epoch read failure denies before anything "+
			"else is loaded, so there is nothing yet worth auditing", len(fs.appended))
	}
}

// TestDecide_AuthFailure_LeavesEpochUnset proves the one legitimate "no
// epoch" case: a token that fails authentication denies before the epoch is
// ever read (authenticateToken runs first — Decide's own doc comment on
// why), so its audited DENY response must leave Epoch unset (nil), the same
// presence-vs-zero-value discipline DecidedSource/DecidedPolicyId already
// use (toResponse's own doc comment). Populating it with 0 instead would be
// indistinguishable from a tenant whose real epoch happens to be 0 — not a
// value this column can hold in production, but exactly the kind of gap a
// proto3 field that quietly lost its `optional` keyword could reopen.
func TestDecide_AuthFailure_LeavesEpochUnset(t *testing.T) {
	fs, req := wellFormedFixture()
	req.Token = "" // authenticateToken's errNoToken path — denies before loadEpochOrDeny ever runs
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v, want a denied decision (fail-closed, audited)", err)
	}
	if resp.Epoch != nil {
		t.Errorf("response Epoch = %d, want unset (nil): authentication failed before the epoch was ever read", resp.GetEpoch())
	}
}

// --- CreateDelegation ---

// TestCreateDelegation_EpochRoundTripsIntoResponse is CreateDelegation's own
// version of TestDecide_EpochRoundTripsIntoResponse: a PEP that has just
// started a session gets an epoch baseline from this call, the same reason
// CreateDelegationResponse.epoch's own doc comment (proto/pdp/v1/pdp.proto)
// gives for carrying it at all.
func TestCreateDelegation_EpochRoundTripsIntoResponse(t *testing.T) {
	fs, req, _ := wellFormedDelegationFixture()
	fs.epoch = 84512
	srv := newDelegationServer(fs, permissiveGrantSet())

	resp, err := srv.CreateDelegation(context.Background(), req)
	if err != nil {
		t.Fatalf("CreateDelegation() error = %v", err)
	}
	if got := resp.GetEpoch(); got != 84512 {
		t.Errorf("response epoch = %d, want %d", got, 84512)
	}
}

// TestCreateDelegation_EpochReadBeforeAgentLoad proves the same V3 ordering
// Decide observes, without needing a hook: CreateDelegation and Decide both
// route through the single shared loadEpochOrDeny (server.go), so there is
// only one call site for this ordering to go wrong at, not a second
// implementation that could independently drift. Configuring BOTH the
// epoch read and the agent load to fail is enough to observe which one is
// actually attempted first — if the agent load ever ran, fs.calls would be
// 2, not 1, regardless of which error the caller ultimately saw.
func TestCreateDelegation_EpochReadBeforeAgentLoad(t *testing.T) {
	fs, req, _ := wellFormedDelegationFixture()
	fs.epochErr = errors.New("epoch read failed")
	fs.agentErr = errors.New("agent load failed -- must never be reached once the epoch read has already failed")
	srv := newDelegationServer(fs, permissiveGrantSet())

	resp, err := srv.CreateDelegation(context.Background(), req)
	if resp != nil {
		t.Fatalf("CreateDelegation() response = %+v, want nil", resp)
	}
	wantCode(t, err, codes.Internal)
	if fs.calls != 1 {
		t.Errorf("store calls = %d, want 1 (LoadTenantEpoch only): the agent must never be loaded "+
			"once the epoch read has already failed", fs.calls)
	}
	if len(fs.created) != 0 {
		t.Errorf("delegation rows created = %d, want 0", len(fs.created))
	}
}

// TestCreateDelegation_EpochReadFailure_Internal isolates the fail-closed
// property TestCreateDelegation_EpochReadBeforeAgentLoad's dual failure
// cannot: only the epoch read fails here, and the agent load is left free
// to succeed. A mutation that swallowed the epoch error and let the call
// continue would sail through the ordering test above (the agent load would
// still fail there, on its own configured error, keeping resp nil for a
// different reason) but would be caught here — the call would proceed all
// the way through a normal grant and return a real, non-nil response.
func TestCreateDelegation_EpochReadFailure_Internal(t *testing.T) {
	fs, req, _ := wellFormedDelegationFixture()
	fs.epochErr = errors.New("connection reset")
	srv := newDelegationServer(fs, permissiveGrantSet())

	resp, err := srv.CreateDelegation(context.Background(), req)
	if resp != nil {
		t.Fatalf("CreateDelegation() response = %+v, want nil: an epoch read failure must deny outright, "+
			"not fall back to a normal grant", resp)
	}
	wantCode(t, err, codes.Internal)
	if len(fs.created) != 0 {
		t.Errorf("delegation rows created = %d, want 0", len(fs.created))
	}
}

// --- IssueToken ---

// TestIssueToken_EpochRoundTripsIntoResponse is IssueToken's own version of
// TestDecide_EpochRoundTripsIntoResponse: a PEP re-issuing an expiring token
// gets a fresh epoch baseline from this call too, the same reason
// IssueTokenResponse.epoch's own doc comment gives.
func TestIssueToken_EpochRoundTripsIntoResponse(t *testing.T) {
	delegationID := uuid.New()
	now := time.Now()
	fs := &fakeStore{delegation: activeDelegation(delegationID, now), epoch: 26839}
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	resp, err := srv.IssueToken(context.Background(), &IssueTokenRequest{
		DelegationId: delegationID.String(),
		TtlSeconds:   600,
	})
	if err != nil {
		t.Fatalf("IssueToken() error = %v", err)
	}
	if got := resp.GetEpoch(); got != 26839 {
		t.Errorf("response epoch = %d, want %d", got, 26839)
	}
}

// TestIssueToken_EpochReadBeforeDelegationLoad is
// TestCreateDelegation_EpochReadBeforeAgentLoad's counterpart: IssueToken's
// next read after the epoch is LoadDelegation, not LoadAgent, but the same
// shared loadEpochOrDeny backs the ordering, so the same dual-failure
// technique proves it here.
func TestIssueToken_EpochReadBeforeDelegationLoad(t *testing.T) {
	delegationID := uuid.New()
	fs := &fakeStore{
		epochErr:      errors.New("epoch read failed"),
		delegationErr: errors.New("delegation load failed -- must never be reached once the epoch read has already failed"),
	}
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	resp, err := srv.IssueToken(context.Background(), &IssueTokenRequest{
		DelegationId: delegationID.String(),
		TtlSeconds:   600,
	})
	if resp != nil {
		t.Fatalf("IssueToken() response = %+v, want nil", resp)
	}
	wantCode(t, err, codes.Internal)
	if fs.calls != 1 {
		t.Errorf("store calls = %d, want 1 (LoadTenantEpoch only): the delegation must never be loaded "+
			"once the epoch read has already failed", fs.calls)
	}
}

// TestIssueToken_EpochReadFailure_Internal isolates the fail-closed property
// the same way TestCreateDelegation_EpochReadFailure_Internal does: only the
// epoch read fails, and the delegation load (a real, active delegation) is
// left free to succeed, so a mutation that swallowed the epoch error would
// have to produce a full, valid IssueTokenResponse to escape detection here.
func TestIssueToken_EpochReadFailure_Internal(t *testing.T) {
	delegationID := uuid.New()
	now := time.Now()
	fs := &fakeStore{delegation: activeDelegation(delegationID, now), epochErr: errors.New("connection reset")}
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	resp, err := srv.IssueToken(context.Background(), &IssueTokenRequest{
		DelegationId: delegationID.String(),
		TtlSeconds:   600,
	})
	if resp != nil {
		t.Fatalf("IssueToken() response = %+v, want nil: an epoch read failure must deny outright, "+
			"not fall back to a normal re-issuance", resp)
	}
	wantCode(t, err, codes.Internal)
}
