package main

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// reapInterval is short enough that a test observing two sweeps finishes
// instantly, and long enough that it is not competing with the scheduler.
// Nothing here sleeps for it: every test below waits on a channel the fake
// reaper writes to, so the suite is bounded by the work, not by the clock.
const reapInterval = time.Millisecond

// syncBuffer is an io.Writer a slog handler can write to from the reaper's
// goroutine while the test reads it from its own. slog gives no ordering or
// exclusion guarantees across goroutines for a plain *bytes.Buffer, and
// -race would (correctly) call that a data race.
type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// runReaper starts reapSpentProofs against reap, waits until it has been
// called n times, then stops it and returns everything that was logged.
//
// It waits on the CALL rather than on elapsed time: a sweep-count assertion
// built on a sleep is the classic flaky test, and it would also be
// measuring the scheduler rather than this function.
func runReaper(t *testing.T, n int, reap reapFunc) string {
	t.Helper()
	var out syncBuffer
	logger := slog.New(slog.NewTextHandler(&out, nil))

	done := make(chan struct{})
	var once sync.Once
	var calls int
	var mu sync.Mutex

	counted := func(ctx context.Context) (int64, error) {
		mu.Lock()
		calls++
		reached := calls >= n
		mu.Unlock()
		reaped, err := reap(ctx)
		if reached {
			once.Do(func() { close(done) })
		}
		return reaped, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		reapSpentProofs(ctx, logger, counted, reapInterval, time.Second)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		cancel()
		<-stopped
		t.Fatalf("reapSpentProofs made fewer than %d sweeps in 10s; logged: %s", n, out.String())
	}
	cancel()
	// Waiting for the goroutine to actually return is what makes reading the
	// buffer below race-free, and it doubles as the proof that cancellation
	// stops the loop at all: a reaper that ignored ctx.Done would hang here.
	<-stopped
	return out.String()
}

// K8's core requirement: a sweep that FAILS says so, at a level a deployment
// that alerts on errors at all will see. A reaper that dies quietly leaves a
// table growing on the decision path until something unrelated falls over,
// and the cause then looks like anything but the reaper.
func TestReapSpentProofs_LogsAFailure(t *testing.T) {
	const marker = "connection refused by the database"
	logged := runReaper(t, 1, func(context.Context) (int64, error) {
		return 0, errors.New(marker)
	})

	if !strings.Contains(logged, marker) {
		t.Errorf("logged output does not carry the reap error:\n%s", logged)
	}
	if !strings.Contains(logged, "level=ERROR") {
		t.Errorf("a failed sweep was not logged at ERROR level — a deployment that alerts on error-level "+
			"lines must catch this without being told about this line specifically:\n%s", logged)
	}
}

// A failure does not stop the schedule. The next sweep still runs, so a
// database that was briefly unreachable recovers on its own rather than
// leaving a live PDP with a reaper that quietly exited hours ago.
func TestReapSpentProofs_KeepsSweepingAfterAFailure(t *testing.T) {
	logged := runReaper(t, 3, func(context.Context) (int64, error) {
		return 0, errors.New("still down")
	})

	if got := strings.Count(logged, "level=ERROR"); got < 3 {
		t.Errorf("ERROR lines = %d, want at least 3: a failing sweep must not stop the schedule:\n%s",
			got, logged)
	}
}

// The COUNT is logged too, and that is not noise. store.ReapSpentProofs'
// own doc comment is explicit that discarding either return value gives up
// half the signal: an error means the reaper did not RUN, while the count is
// what separates a reaper that ran from a reaper that WORKED. Under FORCE
// ROW LEVEL SECURITY a DELETE that RLS filters to nothing returns no error
// at all — so "no error" alone cannot tell a healthy sweep of an empty table
// from one structurally incapable of deleting anything. An operator can only
// treat a reaper pinned at zero against a growing table as an alarm if the
// zero is written down.
func TestReapSpentProofs_LogsTheCountOnSuccess(t *testing.T) {
	logged := runReaper(t, 1, func(context.Context) (int64, error) {
		return 17, nil
	})

	if !strings.Contains(logged, "reaped=17") {
		t.Errorf("logged output does not carry the reaped row count:\n%s", logged)
	}
}

// The zero specifically, because it is the value most tempting to suppress
// as uninteresting and the one that carries the RLS-blocked signal.
func TestReapSpentProofs_LogsAZeroCountToo(t *testing.T) {
	logged := runReaper(t, 1, func(context.Context) (int64, error) {
		return 0, nil
	})

	if !strings.Contains(logged, "reaped=0") {
		t.Errorf("a sweep that deleted nothing was not logged — a reaper pinned at zero against a growing "+
			"table is the same alarm as an error, and invisible if the zero is dropped:\n%s", logged)
	}
}

// Each sweep is bounded, so a stuck DELETE cannot hold a transaction open
// until the process exits and cannot make the next tick stack another on top
// of it. Proven by observing the deadline INSIDE the reap call — the only
// place the derived context is visible — rather than by timing the loop.
func TestReapSpentProofs_BoundsEachSweep(t *testing.T) {
	deadlines := make(chan bool, 1)
	runReaper(t, 1, func(ctx context.Context) (int64, error) {
		_, ok := ctx.Deadline()
		select {
		case deadlines <- ok:
		default:
		}
		return 0, nil
	})

	if !<-deadlines {
		t.Error("the context handed to a sweep carries no deadline: a stuck DELETE would hold its " +
			"transaction open until the process exits")
	}
}
