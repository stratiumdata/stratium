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
