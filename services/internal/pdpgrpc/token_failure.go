// token_failure.go bounds what a token that does not authenticate can cost.
//
// Decide audits that denial, and it is the one audit row a caller needs no
// credential to produce. The append takes the tenant's append lock, which
// every decision and every PAP write (a revocation included) also waits on,
// and the row carries the caller's own tool and subject text. So the rows are
// rate-capped and that text is clipped. A failure over the cap is still
// denied, and is logged; the next row written says how many were left out, so
// the chain never reads as though nothing happened in between.
package pdpgrpc

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/internal/authz"
)

const (
	// maxAuditedCallerTextBytes is how much of a refused tool name or subject
	// an audit row keeps.
	maxAuditedCallerTextBytes = 256
	clippedSuffix             = "...[clipped]"
)

// failureBudget is a token bucket: perSecond rows sustained, burst above it
// (config.FailedTokenAuditPerSecond and FailedTokenAuditBurst). It starts full.
// A zero burst, which config.Load never produces, means no cap.
// ponytail: one bucket per process; key it per agent if one caller's failures
// crowding out another's rows becomes a real complaint.
type failureBudget struct {
	perSecond, burst float64

	mu      sync.Mutex
	tokens  float64
	last    time.Time
	skipped int64
}

// take reports whether a row may be written at now. When it may, skipped is
// how many failures were refused a row since the last one that got one.
func (b *failureBudget) take(now time.Time) (ok bool, skipped int64) {
	if b.burst <= 0 {
		return true, 0 // no cap configured
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.last.IsZero() {
		b.tokens = b.burst
	} else {
		b.tokens = min(b.burst, b.tokens+now.Sub(b.last).Seconds()*b.perSecond)
	}
	b.last = now
	if b.tokens < 1 {
		b.skipped++
		return false, 0
	}
	b.tokens--
	skipped, b.skipped = b.skipped, 0
	return true, skipped
}

// clipCallerText shortens text a caller chose to what an audit row will hold
// when that text was refused or never authenticated, on a character boundary.
func clipCallerText(s string) string {
	if len(s) <= maxAuditedCallerTextBytes {
		return s
	}
	return strings.ToValidUTF8(s[:maxAuditedCallerTextBytes], "") + clippedSuffix
}

// denyUnauthenticated is Decide's answer to a token that did not
// authenticate: a DENY, audited while the budget allows and logged when it
// does not. The log line carries the agent id, already parsed as a UUID, and
// the verifier's own error; never the token, the subject or the tool.
func (s *Server) denyUnauthenticated(
	ctx context.Context, agentID uuid.UUID, action authz.Action, subject string, now time.Time, tokenErr error,
) (*DecideResponse, error) {
	// No delegation: nothing identified one.
	return s.denyUnproven(ctx, agentID, uuid.Nil, action, subject, now, tokenErr)
}

// denyUnproven is the same answer for any credential that fell short: a token
// that did not authenticate (delegationID is uuid.Nil), or a key-bound token
// that did but came without a proof of its key.
func (s *Server) denyUnproven(
	ctx context.Context, agentID, delegationID uuid.UUID, action authz.Action, subject string, now time.Time, credErr error,
) (*DecideResponse, error) {
	ok, skipped := s.failedTokens.take(now)
	if !ok {
		slog.Warn("credential failure denied but not audited: over the audit rate cap",
			"agent_id", agentID.String(), "error", credErr)
		return toResponse(authz.DeriveTierDenial(credErr), nil), nil
	}
	if skipped > 0 {
		credErr = fmt.Errorf("%w [%d earlier credential failures were denied and not recorded]", credErr, skipped)
	}
	action.Tool = clipCallerText(action.Tool)
	// No chain or epoch: nothing has been loaded on this path.
	return s.denyAndAudit(ctx, agentID, delegationID, nil, action, clipCallerText(subject), now, credErr, nil)
}
