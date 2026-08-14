package main

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// cappedReporter calls t.Errorf from any goroutine -- t's own doc comment
// documents Error/Errorf (unlike Fatal/FailNow) as safe for concurrent use
// -- but stops actually reporting after max failures. Without this cap, a
// genuinely broken implementation that fails on nearly every operation in a
// tight, unthrottled polling loop can generate far more failure messages
// than a fixed-size channel could ever buffer; routing them through a
// channel that nothing drains until every producer goroutine has finished
// then deadlocks the producers on their own full channel before any of
// them CAN finish. Reporting directly and capping in-process avoids that
// class of bug entirely rather than sizing a buffer and hoping.
type cappedReporter struct {
	t        *testing.T
	max      int32
	reported int32
}

func (c *cappedReporter) Errorf(format string, args ...any) {
	if atomic.AddInt32(&c.reported, 1) > c.max {
		return
	}
	c.t.Errorf(format, args...)
}

// TestCachePut_ConcurrentWritersNeverProduceATornRead is this task's
// required proof for "concurrent writers do not produce a torn read," and
// the direct catch for the "write in place instead of temp-then-rename"
// mutation: real goroutines, gated behind one shared start channel and
// released together (the shape internal/store's own
// TestIntegration_RevocationEpoch_E2E_MonotonicUnderConcurrentWrites uses
// against a live trigger), racing cachePut and loadCacheEntries against one
// real file on disk -- not simulated interleaving, and not reasoned about
// in prose, per the task brief's own instruction.
//
// The file is seeded near maxCacheEntries BEFORE the burst starts, so every
// writer's read-modify-write below is already encoding/decoding a
// realistically large payload (tens of KB): a single small write is fast
// enough that a naive in-place implementation might never get caught mid-
// write by a polling reader, but a large one gives that reader many more
// scheduler timeslices in which to land inside the window. This is what
// makes a torn read empirically reachable in a test binary's runtime rather
// than only reachable at some vanishingly small probability.
//
// Writers use DISJOINT key ranges (each owns its own slice of indices), so
// nothing here is EXPECTED to collide -- this test isolates the torn-read
// question from the separately-accepted lost-update question, which
// TestCachePut_LostUpdateUnderConcurrencyIsSafe below tests on purpose by
// doing the opposite.
func TestCachePut_ConcurrentWritersNeverProduceATornRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.json")
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	seed := make([]cacheEntry, maxCacheEntries-1)
	for i := range seed {
		seed[i] = testEntry(base, i)
	}
	if err := writeCacheEntries(path, seed); err != nil {
		t.Fatalf("seed cache file: %v", err)
	}

	const writers = 24
	const readers = 8
	const iterationsPerWriter = 20

	report := &cappedReporter{t: t, max: 20}
	var writerWG, readerWG sync.WaitGroup
	start := make(chan struct{})
	stop := make(chan struct{})

	for w := 0; w < writers; w++ {
		writerWG.Add(1)
		go func(w int) {
			defer writerWG.Done()
			<-start
			for k := 0; k < iterationsPerWriter; k++ {
				idx := len(seed) + w*iterationsPerWriter + k
				if err := cachePut(path, testEntry(base, idx)); err != nil {
					report.Errorf("writer %d put index %d: %v", w, idx, err)
				}
			}
		}(w)
	}

	for r := 0; r < readers; r++ {
		readerWG.Add(1)
		go func(r int) {
			defer readerWG.Done()
			<-start
			for {
				select {
				case <-stop:
					return
				default:
				}
				entries, ok := loadCacheEntries(path)
				if !ok {
					// Illegitimate once seeded: writeCacheEntries only ever
					// REPLACES path via rename (this file's own package
					// doc), it never removes it first, so a correctly
					// atomic implementation guarantees path exists and
					// parses for the entire life of this test.
					report.Errorf("reader %d: loadCacheEntries failed on a seeded, never-deleted path", r)
					continue
				}
				for _, e := range entries {
					if !entrySelfConsistent(base, e) {
						report.Errorf("reader %d: entry %+v is internally inconsistent -- "+
							"a decision assembled from two different writes", r, e)
					}
				}
			}
		}(r)
	}

	close(start)
	writerWG.Wait()
	close(stop)
	readerWG.Wait()

	// A final, single-threaded pass: same check, no race left to catch,
	// just confirming the file this burst left behind is itself sane.
	final, ok := loadCacheEntries(path)
	if !ok {
		t.Fatalf("cache file unreadable after the burst completed")
	}
	for _, e := range final {
		if !entrySelfConsistent(base, e) {
			t.Errorf("post-burst entry %+v is internally inconsistent", e)
		}
	}
}

// TestCachePut_LostUpdateUnderConcurrencyIsSafe is the other half of this
// task's concurrency tradeoff (see cache.go's package doc): unlike the
// test above, every writer here targets the SAME small set of keys, so
// collisions -- and therefore lost updates, where a losing writer's rename
// simply never happens to be the last one in -- are expected, not merely
// possible. What must still hold is that every entry that DOES survive the
// burst is completely correct, never a value spliced from two different
// writers' entries for that key.
func TestCachePut_LostUpdateUnderConcurrencyIsSafe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.json")
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	const writers = 30
	const keys = 5 // far fewer keys than writers: heavy, deliberate collision

	var wg sync.WaitGroup
	start := make(chan struct{})
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			<-start
			i := w % keys
			if err := cachePut(path, testEntry(base, i)); err != nil {
				t.Errorf("writer %d: cachePut: %v", w, err)
			}
		}(w)
	}
	close(start)
	wg.Wait()

	entries, ok := loadCacheEntries(path)
	if !ok {
		t.Fatalf("cache file unreadable after a concurrent burst -- a lost update is acceptable, a corrupt file is not")
	}
	if len(entries) > keys {
		t.Fatalf("entry count = %d, want at most %d (one per key) -- a duplicate or stray entry, not merely a lost update",
			len(entries), keys)
	}
	for _, e := range entries {
		if !entrySelfConsistent(base, e) {
			t.Errorf("survivor %+v is internally inconsistent -- losing an update must never mean CORRUPTING the one that wins", e)
		}
	}
}

// TestCachePut_TempFileNeverWiderThanCacheFileMode is the direct catch for
// the "chmod after creation instead of at it" mutation. A final-state check
// on path itself (stat it once after Put returns) cannot distinguish "0600
// from the instant of creation" from "created wide, then chmod'd narrow a
// moment later": both converge to the identical 0600 by the time Put
// returns, because os.Rename carries over whatever mode the source file
// already has, and by the time a rename happens a trailing chmod has
// already run. The only way to see the difference is to catch the TEMP
// file, under its own private name, during the brief window before that
// chmod (if one existed) would have narrowed it -- so this globs for this
// package's own temp-file pattern while a burst of real Puts is in flight
// and Stats whatever it finds.
//
// Correct code (os.CreateTemp, no chmod call anywhere in this file) cannot
// produce a temp file at any mode other than cacheFileMode at any instant
// of its existence, so a single observed violation is conclusive about
// what it MEANS; only whether a given run happens to sample the right
// instant is probabilistic, which is why this reuses the large-seeded-file,
// many-writers shape from the torn-read test above to widen the window a
// poller has to land in.
func TestCachePut_TempFileNeverWiderThanCacheFileMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	seed := make([]cacheEntry, maxCacheEntries-1)
	for i := range seed {
		seed[i] = testEntry(base, i)
	}
	if err := writeCacheEntries(path, seed); err != nil {
		t.Fatalf("seed cache file: %v", err)
	}

	const writers = 16
	const iterationsPerWriter = 30
	const watchers = 4

	report := &cappedReporter{t: t, max: 20}
	var writerWG, watcherWG sync.WaitGroup
	start := make(chan struct{})
	stop := make(chan struct{})

	for w := 0; w < writers; w++ {
		writerWG.Add(1)
		go func(w int) {
			defer writerWG.Done()
			<-start
			for k := 0; k < iterationsPerWriter; k++ {
				idx := len(seed) + w*iterationsPerWriter + k
				if err := cachePut(path, testEntry(base, idx)); err != nil {
					report.Errorf("writer %d put index %d: %v", w, idx, err)
				}
			}
		}(w)
	}

	for g := 0; g < watchers; g++ {
		watcherWG.Add(1)
		go func() {
			defer watcherWG.Done()
			<-start
			for {
				select {
				case <-stop:
					return
				default:
				}
				matches, err := filepath.Glob(filepath.Join(dir, cacheTempPattern))
				if err != nil {
					continue
				}
				for _, m := range matches {
					info, statErr := os.Stat(m)
					if statErr != nil {
						// Renamed or removed between Glob and Stat -- a
						// missed window, not a violation.
						continue
					}
					if perm := info.Mode().Perm(); perm != 0o600 {
						report.Errorf("temp file %s observed at mode %#o, want %#o (0600 set at creation)",
							m, perm, 0o600)
					}
				}
			}
		}()
	}

	close(start)
	writerWG.Wait()
	close(stop)
	watcherWG.Wait()
}
