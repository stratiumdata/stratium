package main

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/stratiumdata/stratium/internal/pdpgrpc"
)

// validityBase is the fixed instant every W3/W4 test in this file anchors
// to -- never time.Now(): a validity check that secretly read the real
// wall clock instead of its own now parameter could still pass every test
// built around a fixture close to the real date, which is exactly the trap
// TestWithinStalenessWindow_UsesInjectedNowNotWallClock below exists to
// rule out.
var validityBase = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// testStaleness is the fixture's staleness window: ten minutes, chosen only
// to sit at a different order of magnitude than the fixture's other two
// time gaps below (CachedAt two minutes back, DelegationExpiresAt two days
// forward), so a mutation that reads the wrong field of cacheEntry cannot
// pass by coincidence.
const testStaleness = 10 * time.Minute

// signedTestToken returns a syntactically real JWT carrying only an "exp"
// claim, signed with a throwaway HMAC key nothing ever checks.
// tokenNotExpired never verifies a signature (see its own doc comment for
// why -- the PEP holds no key to verify one with, by design), so a
// realistic but unverified token is exactly the right fixture: the key and
// algorithm here are arbitrary on purpose.
func signedTestToken(t *testing.T, expiresAt time.Time) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"exp": expiresAt.Unix()})
	s, err := tok.SignedString([]byte("test-signing-key-not-a-real-secret"))
	if err != nil {
		t.Fatalf("sign test token: %v", err)
	}
	return s
}

// tokenWithNoExpClaim returns a syntactically valid JWT that carries no
// "exp" claim at all. Every token this system actually mints has one
// (pdpgrpc/token.go's tokenClaims always sets it, and internal/token.Verify
// requires it to verify at all) -- this exists purely to prove
// tokenNotExpired denies one anyway, since the value it depends on,
// jwt.MapClaims.GetExpirationTime, reports a missing claim as (nil, nil),
// not an error, and this is the one fixture that can actually exercise that
// branch.
func tokenWithNoExpClaim(t *testing.T) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "deleg-no-exp-claim"})
	s, err := tok.SignedString([]byte("test-signing-key-not-a-real-secret"))
	if err != nil {
		t.Fatalf("sign test token: %v", err)
	}
	return s
}

// validFixture returns one baseline (entry, lastKnownEpoch, token, now,
// staleness) tuple that satisfies all four W3 conditions at once. Every
// negative test below takes this and perturbs exactly ONE return value away
// from valid, so a failure isolates to the single condition its own test
// names -- this is what TestCacheEntryUsable_AllFourConditionsPass_IsUsable
// pins as the shared "everything else is fine" baseline the others build
// on, the same shared-baseline-plus-one-override shape
// setAllHookEnv/clearHookEnv (hook_test.go) already uses for config tests.
func validFixture(t *testing.T) (entry cacheEntry, lastKnownEpoch int64, token string, now time.Time, staleness time.Duration) {
	t.Helper()
	now = validityBase
	lastKnownEpoch = 7
	entry = cacheEntry{
		cacheKey: cacheKey{
			DelegationID: "deleg-validity-fixture",
			Tool:         "Bash",
			InputDigest:  sha256.Sum256([]byte("validity fixture input")),
		},
		Decision:            pdpgrpc.Effect_EFFECT_ALLOW,
		Epoch:               lastKnownEpoch,
		DelegationExpiresAt: now.Add(48 * time.Hour),
		CachedAt:            now.Add(-2 * time.Minute),
	}
	token = signedTestToken(t, now.Add(1*time.Hour))
	staleness = testStaleness
	return entry, lastKnownEpoch, token, now, staleness
}

// TestCacheEntryUsable_AllFourConditionsPass_IsUsable is the fixture's own
// positive control: every other test in this file trusts validFixture to
// be usable as built, and this is what proves that trust is warranted.
func TestCacheEntryUsable_AllFourConditionsPass_IsUsable(t *testing.T) {
	entry, epoch, token, now, staleness := validFixture(t)
	if !cacheEntryUsable(entry, epoch, token, now, staleness) {
		t.Error("cacheEntryUsable() = false for a fixture built to satisfy all four W3 conditions, want true")
	}
}

// TestCacheEntryUsable_EpochMismatchDenies defends condition 1 (C20): an
// entry computed under a different epoch than the last one this PEP saw
// must not be served, even though delegation expiry, token validity, and
// staleness are all otherwise fine.
func TestCacheEntryUsable_EpochMismatchDenies(t *testing.T) {
	entry, epoch, token, now, staleness := validFixture(t)
	if cacheEntryUsable(entry, epoch+1, token, now, staleness) {
		t.Error("cacheEntryUsable() = true with a mismatched epoch, want false (C20)")
	}
}

// TestCacheEntryUsable_ExpiredDelegationDenies defends condition 2 (C24's
// time half): a delegation whose own recorded expiry has passed must not be
// served, even under a matching epoch -- the reason V2 keeps expiry out of
// the epoch in the first place: nothing bumps the epoch when a clock
// crosses this value.
func TestCacheEntryUsable_ExpiredDelegationDenies(t *testing.T) {
	entry, epoch, token, now, staleness := validFixture(t)
	entry.DelegationExpiresAt = now.Add(-1 * time.Hour)
	if cacheEntryUsable(entry, epoch, token, now, staleness) {
		t.Error("cacheEntryUsable() = true with an expired delegation, want false (C24 time half)")
	}
}

// TestCacheEntryUsable_ExpiredTokenDenies defends condition 3 (C24's
// credential half): the CALLER's presented token, independent of anything
// the entry itself recorded, must not have expired -- the global "a cache
// hit must not extend a credential's life" rule.
func TestCacheEntryUsable_ExpiredTokenDenies(t *testing.T) {
	entry, epoch, _, now, staleness := validFixture(t)
	expired := signedTestToken(t, now.Add(-1*time.Hour))
	if cacheEntryUsable(entry, epoch, expired, now, staleness) {
		t.Error("cacheEntryUsable() = true with an expired token, want false (C24 credential half)")
	}
}

// TestCacheEntryUsable_OutsideStalenessWindowDenies defends condition 4
// (C19): an entry cached too long ago must not be served even though
// nothing else about it is wrong. entry.DelegationExpiresAt is left at the
// fixture's now+48h -- untouched -- so a mutation that read THAT field
// instead of CachedAt inside withinStalenessWindow would wrongly still
// consider this fresh; only reading the right field catches this.
func TestCacheEntryUsable_OutsideStalenessWindowDenies(t *testing.T) {
	entry, epoch, token, now, staleness := validFixture(t)
	entry.CachedAt = now.Add(-24 * time.Hour)
	if cacheEntryUsable(entry, epoch, token, now, staleness) {
		t.Error("cacheEntryUsable() = true with CachedAt outside the staleness window, want false (C19)")
	}
}

// TestWithinStalenessWindow_BoundaryIsInclusive pins the exact edge
// withinStalenessWindow's doc comment claims (now == CachedAt+staleness is
// still within) rather than leaving "no later than" to be read either way
// by a future change.
func TestWithinStalenessWindow_BoundaryIsInclusive(t *testing.T) {
	entry := cacheEntry{CachedAt: validityBase}
	deadline := validityBase.Add(testStaleness)
	if !withinStalenessWindow(entry, deadline, testStaleness) {
		t.Error("withinStalenessWindow() = false exactly at the deadline, want true (inclusive)")
	}
	if withinStalenessWindow(entry, deadline.Add(time.Nanosecond), testStaleness) {
		t.Error("withinStalenessWindow() = true one nanosecond past the deadline, want false")
	}
}

// TestWithinStalenessWindow_UsesInjectedNowNotWallClock is this task's
// required-but-unprompted mutation (see the task report): it probes a bug
// that could otherwise hide behind every other test in this file passing --
// withinStalenessWindow silently reading the real wall clock instead of its
// own now parameter. Anchoring to 1999, decades before any plausible test
// run, means this stays a valid proof no matter how far in the future this
// suite is ever run, rather than depending on the accidental gap between
// validityBase and whatever the real date happens to be on a given run.
func TestWithinStalenessWindow_UsesInjectedNowNotWallClock(t *testing.T) {
	entry := cacheEntry{CachedAt: time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)}
	staleness := time.Hour

	within := entry.CachedAt.Add(30 * time.Minute)
	if !withinStalenessWindow(entry, within, staleness) {
		t.Error("withinStalenessWindow() = false for now 30m after a 1999 CachedAt with a 1h window, want true -- " +
			"a false here strongly suggests the real current time is being compared instead of the now parameter")
	}

	outside := entry.CachedAt.Add(2 * time.Hour)
	if withinStalenessWindow(entry, outside, staleness) {
		t.Error("withinStalenessWindow() = true for now 2h after a 1999 CachedAt with a 1h window, want false")
	}
}

// TestTokenNotExpired_MalformedTokenDenies defends the fail-closed rule's
// "an unparseable expiry... is a miss" clause against a token that is not
// even a JWT.
func TestTokenNotExpired_MalformedTokenDenies(t *testing.T) {
	if tokenNotExpired("not-a-jwt-at-all", validityBase) {
		t.Error("tokenNotExpired() = true for a string that is not a JWT, want false (fail closed)")
	}
}

// TestTokenNotExpired_MissingExpClaimDenies defends the same fail-closed
// rule against the easy-to-miss shape: a token that parses perfectly well
// but never carries an "exp" claim at all. golang-jwt's
// MapClaims.GetExpirationTime reports that case as (nil, nil) -- no error
// -- so a check that only tested `err != nil` would treat this token as
// valid forever; this test exists specifically to keep that branch honest.
func TestTokenNotExpired_MissingExpClaimDenies(t *testing.T) {
	if tokenNotExpired(tokenWithNoExpClaim(t), validityBase) {
		t.Error("tokenNotExpired() = true for a token with no \"exp\" claim, want false -- " +
			"GetExpirationTime returns (nil, nil) for this, not an error, so err != nil alone would miss it")
	}
}

// TestCacheEntryUsable_EscalationNeverServed defends W4's read-side
// guarantee directly: an ESCALATE entry that satisfies every W3 condition
// -- current epoch, unexpired delegation, valid token, within the window --
// must still never be served. Constructed by hand rather than via
// put, which already refuses to store one (TestCachePut_EscalationNotStored
// below): this is what proves the read side does not simply trust the
// write side to have kept one out.
func TestCacheEntryUsable_EscalationNeverServed(t *testing.T) {
	entry, epoch, token, now, staleness := validFixture(t)
	entry.Decision = pdpgrpc.Effect_EFFECT_ESCALATE
	if cacheEntryUsable(entry, epoch, token, now, staleness) {
		t.Error("cacheEntryUsable() = true for an ESCALATE entry that otherwise passes every W3 condition, want false (W4)")
	}
}

// TestCachePut_EscalationNotStored defends W4's write-side guarantee: a put
// carrying an ESCALATE decision must be refused outright, and must leave no
// trace for a later get to ever find -- not stored with some unservable
// marker, simply never stored.
func TestCachePut_EscalationNotStored(t *testing.T) {
	c := newDecisionCache()
	entry, _, _, _, _ := validFixture(t)
	entry.Decision = pdpgrpc.Effect_EFFECT_ESCALATE

	err := c.put(entry)
	if !errors.Is(err, errEscalationNotCacheable) {
		t.Fatalf("put(ESCALATE) error = %v, want errEscalationNotCacheable", err)
	}
	if _, ok := c.get(entry.cacheKey); ok {
		t.Error("get() found an entry after a refused ESCALATE put, want nothing ever stored")
	}
}

// TestCacheGetValid_LayersUsabilityOverGet proves getValid is genuinely
// doing more than get: the same entry is a hit while every W3 condition
// holds and a miss once one stops holding (here the epoch: a second entry
// raises the cache's own maxEpoch past it) -- while get itself still finds
// it.
func TestCacheGetValid_LayersUsabilityOverGet(t *testing.T) {
	c := newDecisionCache()
	entry, epoch, token, now, staleness := validFixture(t)
	mustCachePut(t, c, entry)

	got, ok := c.getValid(entry.cacheKey, token, now, staleness)
	if !ok {
		t.Fatalf("getValid() ok = false for a fully valid entry, want a hit")
	}
	if got.Decision != entry.Decision {
		t.Errorf("getValid() Decision = %v, want %v", got.Decision, entry.Decision)
	}

	newer := entry
	newer.cacheKey = cacheKey{DelegationID: entry.DelegationID, Tool: "OtherTool", InputDigest: sha256.Sum256([]byte("other"))}
	newer.Epoch = epoch + 1
	mustCachePut(t, c, newer)

	if _, ok := c.get(entry.cacheKey); !ok {
		t.Fatalf("get() ok = false, want the seeded entry still found by the bare store")
	}
	if _, ok := c.getValid(entry.cacheKey, token, now, staleness); ok {
		t.Error("getValid() ok = true for an entry get finds but whose epoch is below the cache's max, want a miss")
	}
}

// clearCacheEnv clears cacheConfig's one required variable, mirroring
// clearHookEnv (hook_test.go) for the same reason: each subtest starts from
// a known-empty baseline regardless of the ambient environment, and
// t.Setenv restores it afterward so subtests never leak into one another.
func clearCacheEnv(t *testing.T) {
	t.Helper()
	t.Setenv(cacheStalenessWindowEnv, "")
}

func TestLoadCacheConfigFromEnv(t *testing.T) {
	t.Run("set", func(t *testing.T) {
		clearCacheEnv(t)
		t.Setenv(cacheStalenessWindowEnv, "10m")

		cfg, err := loadCacheConfigFromEnv()
		if err != nil {
			t.Fatalf("loadCacheConfigFromEnv() error = %v, want nil", err)
		}
		if cfg.StalenessWindow != 10*time.Minute {
			t.Errorf("StalenessWindow = %v, want 10m", cfg.StalenessWindow)
		}
	})

	// Only one required variable exists in cacheConfig, but the missing-key
	// check still goes through the same requiredEnv/missingConfigError
	// machinery every other loader uses (config.go) -- see
	// TestMissingConfig_NamesEveryMissingKeyAcrossLoaders below for the test
	// that actually exercises "names every missing key" with more than one
	// key in play, which a single-field config cannot do on its own.
	t.Run("missing is named in the error", func(t *testing.T) {
		clearCacheEnv(t)

		_, err := loadCacheConfigFromEnv()
		if err == nil {
			t.Fatalf("loadCacheConfigFromEnv() error = nil, want an error naming %s", cacheStalenessWindowEnv)
		}
		if !strings.Contains(err.Error(), cacheStalenessWindowEnv) {
			t.Errorf("loadCacheConfigFromEnv() error = %q, want it to name %s", err.Error(), cacheStalenessWindowEnv)
		}
	})

	// The same three bad shapes TestLoadHookConfigFromEnv's own "invalid
	// duration" subtest checks for every duration field it loads
	// (unparseable, zero, negative) -- requiredDuration (config.go) is
	// shared machinery, but this proves cacheConfig's own loader actually
	// calls it rather than parsing the value some other way.
	t.Run("invalid duration", func(t *testing.T) {
		for _, bad := range []struct {
			name  string
			value string
		}{
			{"not a duration", "not-a-duration"},
			{"zero", "0s"},
			{"negative", "-5m"},
		} {
			t.Run(bad.name, func(t *testing.T) {
				clearCacheEnv(t)
				t.Setenv(cacheStalenessWindowEnv, bad.value)

				_, err := loadCacheConfigFromEnv()
				if err == nil {
					t.Fatalf("loadCacheConfigFromEnv() error = nil, want an error naming %s", cacheStalenessWindowEnv)
				}
				if !strings.Contains(err.Error(), cacheStalenessWindowEnv) {
					t.Errorf("loadCacheConfigFromEnv() error = %q, want it to name %s", err.Error(), cacheStalenessWindowEnv)
				}
			})
		}
	})
}

// TestMissingConfig_NamesEveryMissingKeyAcrossLoaders is the genuine proof
// of "a missing required config value fails startup naming all missing
// keys": cacheConfig alone has only one required variable, so it cannot
// exercise the PLURAL case by itself. Composed with hookConfig's own
// loader the same way runMCPCmd does (combineConfigErrors, mcp.go), a gap in EACH independently
// loaded config must be named in the one combined error together, not just
// whichever loader happened to run first.
func TestMissingConfig_NamesEveryMissingKeyAcrossLoaders(t *testing.T) {
	clearHookEnv(t)
	setAllHookEnv(t, map[string]string{"STRATIUM_PEP_PDP_ADDR": ""})
	clearCacheEnv(t)

	_, hookErr := loadHookConfigFromEnv()
	_, cacheErr := loadCacheConfigFromEnv()
	err := combineConfigErrors(hookErr, cacheErr)
	if err == nil {
		t.Fatalf("combineConfigErrors() = nil, want an error naming both missing keys")
	}
	for _, want := range []string{"STRATIUM_PEP_PDP_ADDR", cacheStalenessWindowEnv} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("combined error = %q, want it to name %s", err.Error(), want)
		}
	}
}
