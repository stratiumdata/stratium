// Command stratium-pdp: reaper.go is the schedule spec §4.7.2 K8 requires for
// the spent-proof table. store.ReapSpentProofs deletes this tenant's expired
// rows; until this file existed, nothing called it — the table would have
// grown on the decision path forever.
package main

import (
	"context"
	"log/slog"
	"time"
)

// reapFunc is store.ReapSpentProofs' shape. A function value rather than a
// one-method interface, deliberately: the only thing this file needs is
// "something that sweeps and reports how much it swept," repo.ReapSpentProofs
// satisfies it as a method value with no adapter, and a test can be a closure
// instead of a type. An interface here would have exactly one production
// implementation and one test double, which is the definition of an
// abstraction that pays for nothing.
type reapFunc func(context.Context) (int64, error)

// reapSpentProofs sweeps expired spent-proof rows every interval until ctx is
// done. Blocking; run it in a goroutine.
//
// # Why its failure is logged, and why a log line is enough
//
// K8: "the reaper's failure must be visible rather than silently letting the
// table grow." A reaper that dies quietly leaves a table growing on the
// decision path until something unrelated falls over — a query plan tips, a
// disk fills — and the cause looks like anything but the reaper, which is the
// most expensive kind of failure to diagnose because nothing points at it.
//
// A log line is the right visibility mechanism here rather than the weakest
// one available, for a reason this codebase has already settled once: there
// is no metrics surface at all in any binary (no Prometheus, no
// OpenTelemetry), so a metric would mean introducing one for a single
// counter, while slog is already how this process says everything else it has
// to say — see internal/pdpgrpc.honoredOverrides' own doc comment, which
// reached this conclusion for the dropped-override warning. Error level, so a
// deployment that alerts on error-level lines at all alerts on this without
// being told about it specifically.
//
// # Both signals are logged, not just the failure
//
// store.ReapSpentProofs returns a count as well as an error and its doc
// comment is explicit that discarding either gives up half the signal: a
// non-nil error is a reaper that did not RUN, while the count is what
// separates a reaper that ran from a reaper that WORKED. Under FORCE ROW
// LEVEL SECURITY a DELETE that RLS silently filters to nothing returns no
// error at all — so "no error" alone cannot distinguish a healthy sweep of an
// empty table from a sweep that is structurally incapable of deleting
// anything. An operator seeing a reaper pinned at zero against a table that
// keeps growing should treat it as the same alarm as an error, and that
// comparison is only possible if the zero is written down.
//
// # A sweep does not outlive its own interval's worth of patience
//
// Each sweep gets timeout (cfg.DBTimeout) rather than running unbounded: a
// stuck DELETE holding a transaction open until the process exits would be a
// second, quieter failure on top of the first, and the next tick would stack
// another on it. A sweep cancelled by that deadline surfaces as the error
// above, which is exactly right — it did not run.
//
// The ticker drops ticks that arrive while a sweep is still going (time.
// Ticker's documented behaviour for a channel of capacity one), so a slow
// database cannot make this accumulate goroutines or queue work. Reaping is
// idempotent — the next sweep deletes whatever the skipped one would have —
// so there is nothing to catch up on.
func reapSpentProofs(ctx context.Context, logger *slog.Logger, reap reapFunc, interval, timeout time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweepCtx, cancel := context.WithTimeout(ctx, timeout)
			reaped, err := reap(sweepCtx)
			cancel()
			if err != nil {
				logger.Error("spent-proof reap failed: expired rows are accumulating on the decision path",
					"error", err, "interval", interval)
				continue
			}
			logger.Info("spent-proof reap complete", "reaped", reaped, "interval", interval)
		}
	}
}
