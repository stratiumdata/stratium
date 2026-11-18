package main

import (
	"sync"
	"testing"
	"time"
)

// TestDecisionCache_ConcurrentPutAndGet races writers and readers on ONE
// decisionCache, the way mcp's per-tools/call goroutines do
// (mcp_authorize.go). It is meaningful only under `go test -race`: the race
// detector is what turns a method that touches c.entries without c.mu into
// a failure. The assertions below add the logical half -- a reader must
// only ever see an entry that one whole put stored (entrySelfConsistent,
// cache_test.go), never fields from two.
//
// The cache is capped small so eviction's in-place sort (evictOldest) runs
// on nearly every put while readers are scanning.
func TestDecisionCache_ConcurrentPutAndGet(t *testing.T) {
	const (
		writers          = 8
		readers          = 8
		entriesPerWriter = 200
		capEntries       = 32
	)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	token := signedTestToken(t, base.Add(48*time.Hour))
	c := newDecisionCache()
	c.max = capEntries

	start := make(chan struct{})
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			<-start
			for i := 0; i < entriesPerWriter; i++ {
				if err := c.put(testEntry(base, w*entriesPerWriter+i)); err != nil {
					t.Errorf("put: %v", err)
					return
				}
			}
		}(w)
	}
	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func(r int) {
			defer wg.Done()
			<-start
			for i := 0; i < writers*entriesPerWriter; i++ {
				key := testEntry(base, (i+r)%(writers*entriesPerWriter)).cacheKey
				if e, ok := c.get(key); ok && !entrySelfConsistent(base, e) {
					t.Errorf("get() returned an entry no single put stored: %+v", e)
					return
				}
				if e, ok := c.getValid(key, token, base.Add(time.Hour), 24*time.Hour); ok && !entrySelfConsistent(base, e) {
					t.Errorf("getValid() returned an entry no single put stored: %+v", e)
					return
				}
				_ = c.maxEpoch()
			}
		}(r)
	}
	close(start)
	wg.Wait()

	if got := len(c.entries); got != capEntries {
		t.Errorf("entry count after the burst = %d, want exactly the cap %d", got, capEntries)
	}
	for _, e := range c.entries {
		if !entrySelfConsistent(base, e) {
			t.Errorf("cache holds an entry no single put stored: %+v", e)
		}
	}
}

// TestDecisionCache_ConcurrentUpsertsOfOneKey_LeaveOneEntry: many goroutines
// storing the SAME key must leave exactly one entry for it. An unlocked
// find-then-append would let two of them both miss and both append.
func TestDecisionCache_ConcurrentUpsertsOfOneKey_LeaveOneEntry(t *testing.T) {
	const goroutines = 32
	c := newDecisionCache()
	entry := testEntry(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), 1)

	start := make(chan struct{})
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if err := c.put(entry); err != nil {
				t.Errorf("put: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := len(c.entries); got != 1 {
		t.Errorf("entry count = %d, want 1 (every put carried the same key)", got)
	}
}
