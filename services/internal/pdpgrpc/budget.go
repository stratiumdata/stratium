// budget.go holds each session to a rate of calls.
//
// A session is a root delegation and every delegation made under it, the
// same unit the pending-approval maximum uses. Every token names its session
// (rootClaim), so a call is counted before anything is read from the store,
// and delegating to a sub-agent does not buy a second budget.
//
// A refused call costs no store work. Refusals are still on the record: an
// audit entry says how many there were, at most one entry a minute for each
// session, so the record of a flood is not itself a flood.
//
// The count is shared by every PDP for the tenant when the server is given a
// SessionBudgetStore, which the PDP binary always does: each takes tokens
// from the store a block at a time. A server without one counts alone.
package pdpgrpc

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/internal/authz"
	"github.com/stratiumdata/stratium/pkg/audit"
)

const (
	// eventTypeCallBudgetExceeded is the audit entry for refused calls.
	eventTypeCallBudgetExceeded = "call_budget_exceeded"
	// budgetAuditInterval is the least time between two such entries for
	// one session.
	budgetAuditInterval = time.Minute
	// budgetSweepInterval is how often idle sessions are forgotten.
	budgetSweepInterval = time.Minute
	// leaseRetryInterval is how long a session is counted by this process
	// alone after the shared store could not be asked, before it is asked
	// again. leaseFailureLogInterval is the least time between log lines
	// about that.
	leaseRetryInterval = 5 * time.Second
	// leaseTimeout is how long one request for tokens may take.
	leaseTimeout            = time.Second
	leaseFailureLogInterval = time.Minute
	// budgetActor is who a refused-calls entry is attributed to when the
	// call carried no subject of its own.
	budgetActor = "stratium-pdp"
)

// SessionBudgetStore is where a session's budget is kept when it is shared by
// every PDP for the tenant. *store.Store in production.
type SessionBudgetStore interface {
	// LeaseSessionTokens takes up to want tokens from session's budget, of
	// burst tokens refilling at perSecond, and returns how many it got.
	LeaseSessionTokens(ctx context.Context, session uuid.UUID, burst, perSecond float64, want int) (int, error)
}

type sessionBudgets struct {
	perSecond, burst float64

	// shared, when set, holds the budgets (WithSessionBudgetStore). This
	// process then takes a session's tokens from it a block at a time and
	// spends them from memory, so the store is written about once per block
	// and the rate holds across every PDP that shares it. Left nil, this
	// process keeps the whole count itself.
	shared SessionBudgetStore

	mu                  sync.Mutex
	sessions            map[uuid.UUID]*sessionBucket
	lastSweep           time.Time
	lastLeaseFailureLog time.Time
}

type sessionBucket struct {
	// mu orders one session's calls, a lease included, without holding up
	// any other session's.
	mu sync.Mutex

	// tokens is the bucket itself when this process keeps the count.
	tokens float64
	// leased is what is left of the last block taken from the shared store,
	// and nextLease the earliest another may be asked for after the store
	// said there were none: a refused call must not cost a store call each.
	leased    int
	nextLease time.Time
	// alone is set while the shared store cannot be asked: this process
	// counts the session itself, in tokens, until nextLease.
	alone bool

	last time.Time
	// refused counts calls refused since the last audit entry about them.
	refused   int64
	lastAudit time.Time
}

// take counts one call against session at now and reports whether it may go
// ahead. report, when above zero, is how many calls have been refused since
// the last audit entry said so: the caller writes one now.
//
// A shared store that cannot be asked does not fail the call. This process
// counts the session on its own until the store answers again, so the call is
// still held to the rate, by this PDP if not across all of them.
//
// A zero burst, which config.Load never produces, means no budget.
func (b *sessionBudgets) take(ctx context.Context, session uuid.UUID, now time.Time) (ok bool, report int64) {
	if b.burst <= 0 {
		return true, 0
	}
	s := b.bucket(session, now)
	s.mu.Lock()
	defer s.mu.Unlock()

	alone := b.shared == nil || s.alone
	if !alone && s.leased == 0 && !now.Before(s.nextLease) {
		// Its own short deadline: a store that hangs must not use up the
		// call's time before the decision has begun.
		leaseCtx, cancel := context.WithTimeout(ctx, leaseTimeout)
		got, err := b.shared.LeaseSessionTokens(leaseCtx, session, b.burst, b.perSecond, b.block())
		cancel()
		switch {
		case err != nil:
			// Count alone from here and ask the store again after a pause,
			// not on every call. tokens is this process's own bucket for the
			// session: full the first time, since nothing has drawn on it,
			// and where it was left on any later one, so an outage is not a
			// fresh burst at every retry.
			b.logLeaseFailure(now, err)
			s.alone, s.nextLease = true, now.Add(leaseRetryInterval)
			alone = true
		case got == 0:
			// One token's worth of time: there cannot be one sooner.
			s.nextLease = now.Add(time.Duration(float64(time.Second) / b.perSecond))
		default:
			s.leased = got
		}
	}

	if alone {
		s.tokens = min(b.burst, s.tokens+now.Sub(s.last).Seconds()*b.perSecond)
		if ok = s.tokens >= 1; ok {
			s.tokens--
		}
		// Back to the shared store once the pause is over. Whatever this
		// process allowed meanwhile was never taken from it.
		if s.alone && !now.Before(s.nextLease) {
			s.alone = false
		}
	} else if ok = s.leased > 0; ok {
		s.leased--
	}
	s.last = now

	if !ok {
		s.refused++
	}
	if s.refused > 0 && now.Sub(s.lastAudit) >= budgetAuditInterval {
		report, s.refused, s.lastAudit = s.refused, 0, now
	}
	return ok, report
}

// logLeaseFailure says the shared store could not be asked, at most once
// every leaseFailureLogInterval however many calls find it so.
func (b *sessionBudgets) logLeaseFailure(now time.Time, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if now.Sub(b.lastLeaseFailureLog) < leaseFailureLogInterval {
		return
	}
	b.lastLeaseFailureLog = now
	slog.Warn("session budgets cannot be shared: this PDP is counting sessions on its own until the store answers",
		"error", err)
}

// block is how many tokens are taken from the shared store at once: about a
// second's worth, and never more than the bucket holds.
func (b *sessionBudgets) block() int {
	return max(1, int(min(math.Ceil(b.perSecond), b.burst)))
}

// bucket returns session's bucket, making a full one if it has none.
func (b *sessionBudgets) bucket(session uuid.UUID, now time.Time) *sessionBucket {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sweep(now)
	s := b.sessions[session]
	if s == nil {
		if b.sessions == nil {
			b.sessions = map[uuid.UUID]*sessionBucket{}
		}
		s = &sessionBucket{tokens: b.burst, last: now}
		b.sessions[session] = s
	}
	return s
}

// sweep forgets sessions with nothing left to say: idle for as long as a
// bucket takes to fill, and no refusals waiting to be reported. Tokens such a
// session still held from the shared store go with it. Called with mu held.
func (b *sessionBudgets) sweep(now time.Time) {
	if now.Sub(b.lastSweep) < budgetSweepInterval {
		return
	}
	b.lastSweep = now
	full := time.Duration(b.burst / b.perSecond * float64(time.Second))
	for id, s := range b.sessions {
		// A bucket in use right now is not idle.
		if !s.mu.TryLock() {
			continue
		}
		idle := s.refused == 0 && now.Sub(s.last) >= full
		s.mu.Unlock()
		if idle {
			delete(b.sessions, id)
		}
	}
}

// WithSessionBudgetStore has every PDP that shares st share one budget for
// each session. Without it this process counts on its own.
func (s *Server) WithSessionBudgetStore(st SessionBudgetStore) *Server {
	s.budgets.shared = st
	return s
}

// withinBudget counts one call against session and reports whether it may go
// ahead, writing the audit entry about refused calls when one is due. actor
// is who the entry is attributed to; agentID may be nil.
func (s *Server) withinBudget(
	ctx context.Context, session, delegationID uuid.UUID, agentID *uuid.UUID, actor string, now time.Time,
) bool {
	ok, report := s.budgets.take(ctx, session, now)
	if report == 0 {
		return ok
	}
	entry := audit.Entry{
		TenantID:      s.cfg.TenantID,
		OccurredAt:    now,
		EventType:     eventTypeCallBudgetExceeded,
		Actor:         actor,
		AgentID:       agentID,
		DelegationID:  &delegationID,
		DeclaredTier:  auditDeclaredTierAbsent,
		Decision:      authz.EffectDeny.String(),
		DeniedAtDepth: noDenial,
		Reason: fmt.Sprintf("session %s: %d calls refused for arriving faster than %g a second (burst %g)",
			session, report, s.budgets.perSecond, s.budgets.burst),
	}
	// A failure here must not turn an allowed call into a refused one, and a
	// refused call is refused either way.
	if err := s.store.AppendAudit(ctx, entry); err != nil {
		slog.Error("could not record refused calls in the audit chain",
			"session", session.String(), "refused", report, "error", err)
	}
	return ok
}

// errOverBudget is the reason given for a call refused by its session's
// budget.
func (s *Server) errOverBudget() error {
	return fmt.Errorf("this session is making calls faster than the PDP allows (%g a second); try again shortly",
		s.budgets.perSecond)
}
