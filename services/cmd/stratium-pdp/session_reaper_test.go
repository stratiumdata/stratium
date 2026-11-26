package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A sweep keeps going while batches come back full, and stops at the first
// short one.
func TestSweepSessions_RunsBatchesUntilOneIsShort(t *testing.T) {
	cutoff := time.Now().Add(-time.Hour)
	results := []int{sessionReapBatch, sessionReapBatch, 7}
	calls := 0
	reap := func(_ context.Context, got time.Time, batch int) (int, error) {
		if !got.Equal(cutoff) || batch != sessionReapBatch {
			t.Errorf("reap(cutoff %s, batch %d), want (%s, %d)", got, batch, cutoff, sessionReapBatch)
		}
		n := results[calls]
		calls++
		return n, nil
	}

	total, err := sweepSessions(context.Background(), reap, cutoff, time.Second)
	if err != nil || total != 2*sessionReapBatch+7 || calls != 3 {
		t.Fatalf("sweepSessions() = %d, %v after %d batches; want %d, nil after 3", total, err, calls, 2*sessionReapBatch+7)
	}
}

// A failing batch ends the sweep and reports what had gone before it.
func TestSweepSessions_StopsAtAFailure(t *testing.T) {
	failure := errors.New("database is down")
	calls := 0
	reap := func(context.Context, time.Time, int) (int, error) {
		calls++
		if calls == 2 {
			return 0, failure
		}
		return sessionReapBatch, nil
	}

	total, err := sweepSessions(context.Background(), reap, time.Now(), time.Second)
	if !errors.Is(err, failure) || total != sessionReapBatch || calls != 2 {
		t.Fatalf("sweepSessions() = %d, %v after %d batches; want %d and the failure after 2", total, err, calls, sessionReapBatch)
	}
}
