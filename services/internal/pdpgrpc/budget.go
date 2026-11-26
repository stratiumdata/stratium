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
// ponytail: buckets live in this process's memory. Several PDPs for one
// tenant each allow the full rate; share the counters (the database, or a
// cache) if the rate has to hold across them.
package pdpgrpc

import (
	"context"
	"fmt"
	"log/slog"
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
	// budgetActor is who a refused-calls entry is attributed to when the
	// call carried no subject of its own.
	budgetActor = "stratium-pdp"
)

type sessionBudgets struct {
	perSecond, burst float64

	mu        sync.Mutex
	sessions  map[uuid.UUID]*sessionBucket
	lastSweep time.Time
}

type sessionBucket struct {
	tokens float64
	last   time.Time
	// refused counts calls refused since the last audit entry about them.
	refused   int64
	lastAudit time.Time
}

// take counts one call against session at now and reports whether it may go
// ahead. report, when above zero, is how many calls have been refused since
// the last audit entry said so: the caller writes one now.
//
// A zero burst, which config.Load never produces, means no budget.
func (b *sessionBudgets) take(session uuid.UUID, now time.Time) (ok bool, report int64) {
	if b.burst <= 0 {
		return true, 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sweep(now)

	s := b.sessions[session]
	if s == nil {
		if b.sessions == nil {
			b.sessions = map[uuid.UUID]*sessionBucket{}
		}
		s = &sessionBucket{tokens: b.burst}
		b.sessions[session] = s
	} else {
		s.tokens = min(b.burst, s.tokens+now.Sub(s.last).Seconds()*b.perSecond)
	}
	s.last = now

	if ok = s.tokens >= 1; ok {
		s.tokens--
	} else {
		s.refused++
	}
	if s.refused > 0 && now.Sub(s.lastAudit) >= budgetAuditInterval {
		report, s.refused, s.lastAudit = s.refused, 0, now
	}
	return ok, report
}

// sweep forgets sessions with nothing left to say: a full bucket and no
// refusals waiting to be reported. Called with mu held.
func (b *sessionBudgets) sweep(now time.Time) {
	if now.Sub(b.lastSweep) < budgetSweepInterval {
		return
	}
	b.lastSweep = now
	full := time.Duration(b.burst / b.perSecond * float64(time.Second))
	for id, s := range b.sessions {
		if s.refused == 0 && now.Sub(s.last) >= full {
			delete(b.sessions, id)
		}
	}
}

// withinBudget counts one call against session and reports whether it may go
// ahead, writing the audit entry about refused calls when one is due. actor
// is who the entry is attributed to; agentID may be nil.
func (s *Server) withinBudget(
	ctx context.Context, session, delegationID uuid.UUID, agentID *uuid.UUID, actor string, now time.Time,
) bool {
	ok, report := s.budgets.take(session, now)
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
