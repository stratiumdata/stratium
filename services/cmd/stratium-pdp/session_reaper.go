package main

import (
	"context"
	"log/slog"
	"time"
)

// sessionReapBatch is how many sessions one transaction deletes. A sweep runs
// as many batches as it takes.
const sessionReapBatch = 200

// reapSessionsFunc deletes up to batch sessions that wholly expired before
// cutoff and returns how many it deleted (store.ReapExpiredSessions).
type reapSessionsFunc func(ctx context.Context, cutoff time.Time, batch int) (int, error)

// reapSessions deletes, every interval, the sessions that wholly expired more
// than retention ago, until ctx ends. Each batch gets timeout.
//
// A failed sweep is logged and tried again at the next interval: the rows it
// would have deleted are old and allow nothing, so the cost of a miss is
// space.
func reapSessions(
	ctx context.Context, logger *slog.Logger, reap reapSessionsFunc, retention, interval, timeout time.Duration,
) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			deleted, err := sweepSessions(ctx, reap, time.Now().Add(-retention), timeout)
			if err != nil {
				logger.Error("session reap failed: expired sessions are accumulating",
					"error", err, "deleted_before_failure", deleted, "interval", interval)
				continue
			}
			if deleted > 0 {
				logger.Info("session reap complete", "sessions_deleted", deleted, "retention", retention)
			}
		}
	}
}

// sweepSessions runs batches until one comes back short, and returns how many
// sessions went.
func sweepSessions(ctx context.Context, reap reapSessionsFunc, cutoff time.Time, timeout time.Duration) (int, error) {
	total := 0
	for {
		batchCtx, cancel := context.WithTimeout(ctx, timeout)
		n, err := reap(batchCtx, cutoff, sessionReapBatch)
		cancel()
		total += n
		if err != nil || n < sessionReapBatch {
			return total, err
		}
	}
}

// reapBudgetsFunc deletes the budget rows of sessions untouched since
// idleSince and returns how many went (store.ReapSessionBudgets).
type reapBudgetsFunc func(ctx context.Context, idleSince time.Time) (int64, error)

// budgetIdleTime is how long a session's budget row may sit untouched before
// it is deleted: as long as an empty bucket takes to fill, and at least an
// hour. A row left that long is full, which is what having no row means.
func budgetIdleTime(perSecond float64, burst int) time.Duration {
	fill := time.Duration(float64(burst) / perSecond * float64(time.Second))
	return max(time.Hour, fill)
}

// reapSessionBudgets deletes, every interval, the budget rows of sessions
// nobody has called under for idle, until ctx ends. A failed sweep is logged
// and tried again: the rows it would have deleted cost only space.
func reapSessionBudgets(
	ctx context.Context, logger *slog.Logger, reap reapBudgetsFunc, idle, interval, timeout time.Duration,
) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweepCtx, cancel := context.WithTimeout(ctx, timeout)
			_, err := reap(sweepCtx, time.Now().Add(-idle))
			cancel()
			if err != nil {
				logger.Error("session budget reap failed: rows for idle sessions are accumulating",
					"error", err, "interval", interval)
			}
		}
	}
}
