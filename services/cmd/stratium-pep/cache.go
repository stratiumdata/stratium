// cache.go is the PEP's decision cache (spec §4.8, §4.8.2 W1-W4): an
// in-memory store, plus whether a retrieved entry is still USABLE (epoch
// match, delegation not expired, token still valid, within the staleness
// window -- W3) and W4's rule that an ESCALATE is never cached or served
// (see "Validity" below). This file never imports internal/authz, and the
// only thing it inspects Decision for is refusing to store or serve an
// ESCALATE -- it never inspects one to CLASSIFY or COMBINE anything:
// replaying a verdict the PDP already produced, or declining to, is not the
// same act as deriving one.
//
// # Memory only
//
// The cache lives in process memory and nowhere else, so that the only
// decisions ever replayed are ones THIS process received from the PDP. A
// decision is never read from a file: the agent being policed runs as the
// same OS user as the PEP, so no location on disk can vouch for where an
// entry came from. The consequences follow directly. mcp, one long-running
// process, holds one decisionCache for its lifetime (mcp.go's runMCP), and
// it starts empty on every start. hook, a new process per tool call, has
// nothing to remember between calls and therefore has no cache at all --
// it asks the PDP every time (hook.go).
//
// Key and stored fields (W2): an entry is keyed by (delegation id, tool,
// input digest) -- keyed on the DELEGATION rather than the token because a
// token rotates while the delegation persists, so keying on the token would
// discard the whole cache on every reissue -- and records the decision, the
// epoch it was computed under, the delegation's own recorded expiry, and
// when this process cached it. InputDigest reuses sha256.Sum256(raw_input)
// exactly as internal/pdpgrpc/server.go's appendAudit already computes it
// for the audit chain, rather than inventing a second notion of request
// identity for the same bytes. Epoch and CachedAt are plain, non-optional
// values (not pointers, unlike pdpgrpc.DecideResponse.Epoch): a decision
// worth caching came from a call that read a real epoch, and CachedAt is
// supplied by the caller rather than stamped internally with time.Now(), so
// a caller can use one captured instant across a whole decide-and-cache
// flow and so this file's own tests can construct exact, reproducible
// eviction orders.
//
// # Concurrency
//
// mcp authorizes each tools/call on its own goroutine (mcp_authorize.go), so
// every method takes decisionCache.mu. getValid reads the cache's highest
// epoch and looks the entry up under ONE acquisition, so a concurrent put
// that raises the epoch cannot land between the two.
//
// # Eviction
//
// maxCacheEntries bounds the cache by entry COUNT. Age decides WHICH
// entries an over-cap put evicts (oldest CachedAt first -- evictOldest
// below), not WHEN eviction triggers; the staleness window ("Validity")
// separately decides whether a surviving entry may still be served.
//
// # Validity
//
// W3 is four independent conditions, ALL required, each closing a
// different conformance property: epochCurrent (C20), delegationNotExpired
// (C24's time half), tokenNotExpired (C24's credential half), and
// withinStalenessWindow (C19). cacheEntryUsable combines the four -- plus
// W4's rule below -- and getValid applies the combination on top of a
// lookup, so a caller never sees "a hit that turned out to be unusable" as
// a distinct outcome from an ordinary miss; fail closed means the two are
// indistinguishable on purpose.
//
// withinStalenessWindow's clock runs from the ENTRY'S OWN CachedAt, not
// from the most recent successful PDP contact of any kind. Both are
// defensible, and they differ sharply during an outage that starts right
// after a busy period: "any kind" would let one call's success silently
// vouch for every OTHER entry's freshness too, so the whole cache would
// read as fresh right up until staleness-window after that last unrelated
// call, then go stale all at once. Per-entry CachedAt instead lets each
// entry age out on its own schedule, on the strength of only its own
// evidence. Chosen because: (1) it needs no shared "last contact" clock
// that every code path would have to remember to update; (2) it is the
// strictly more conservative reading -- an entry never gets to borrow
// freshness from a call it was not itself part of; and (3) it gives an
// operator's staleness-window setting one bound that means the same thing
// for every decision: no cached verdict is EVER served more than that long
// after the PDP actually computed it. The cost an operator should expect in
// exchange: during an outage, calls whose entries happen to be older start
// denying sooner than calls whose entries are newer -- the cache empties
// out over the course of the window rather than holding together and then
// dropping all at once.
//
// tokenNotExpired decodes the caller's presented token's own "exp" claim
// without verifying its signature, deliberately: internal/token's own
// package doc makes the PDP the ONLY verifier (spec K2 -- no JWKS document
// distributes a key anyone else could check a signature against), so the
// PEP has never held the means to verify a token on ANY path, cached or
// forwarded to Decide. What this condition narrows is specifically "has
// the claimed expiry passed" -- the same claim, the same trust boundary,
// DelegationExpiresAt is itself sourced from (decode the token's "exp"
// claim; pdp.proto's CreateDelegationResponse.token comment), not a new
// capability this file invents.
//
// W4 (an ESCALATE is never cached, spec §4.6) is guarded twice, on
// purpose: put refuses to STORE one, and cacheEntryUsable refuses to SERVE
// one even if a future put lost the guard. The failure is silent if missed
// -- a served ESCALATE either re-blocks a call a human already approved or
// fabricates an approval nobody granted -- so it gets defended at both the
// only door it can be written through and the only door it can be read
// back out of, rather than trusting the first to make the second
// redundant.
package main

import (
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/stratiumdata/stratium/internal/pdpgrpc"
)

// maxCacheEntries bounds the cache's entry count -- see this file's own
// package doc, "Eviction." 500 keeps the linear scan every lookup performs
// trivially small while comfortably covering one agent session's distinct
// tool calls inside any sensible staleness window.
const maxCacheEntries = 500

// cacheKey is spec §4.8.2 W2's tuple: (delegation id, tool, input digest).
// A named struct rather than three positional parameters on every function
// below -- DelegationID and Tool are both plain strings, and this project
// has repeatedly been bitten by values that type-check but are silently
// transposed; naming the fields forces a call site to say which is which.
type cacheKey struct {
	DelegationID string
	Tool         string
	InputDigest  [32]byte
}

// cacheEntry is one cached PDP decision. Decision, Epoch, and
// DelegationExpiresAt are exactly what W3 (cacheEntryUsable, below) needs
// to judge whether a hit is still valid; CachedAt is when this process
// stored it.
// Deliberately not pdpgrpc.DecideResponse or authz.Result: this cache
// replays a verdict, not the machinery that produced it.
type cacheEntry struct {
	cacheKey
	Decision            pdpgrpc.Effect
	Epoch               int64
	DelegationExpiresAt time.Time
	CachedAt            time.Time
}

// decisionCache is the in-memory store -- see the package doc, "Memory
// only," for why there is no other kind. The zero value is not usable;
// build one with newDecisionCache.
type decisionCache struct {
	mu      sync.Mutex
	entries []cacheEntry
	max     int
}

// newDecisionCache returns an empty cache bounded at maxCacheEntries. There
// is deliberately no constructor that takes initial entries: a cache only
// ever learns a decision through put, from a live PDP response.
func newDecisionCache() *decisionCache {
	return &decisionCache{max: maxCacheEntries}
}

// find returns the entry for key. Callers hold c.mu.
func (c *decisionCache) find(key cacheKey) (cacheEntry, bool) {
	for _, e := range c.entries {
		if e.cacheKey == key {
			return e, true
		}
	}
	return cacheEntry{}, false
}

// highestEpoch returns the highest Epoch among the entries, or 0 for an
// empty cache. Callers hold c.mu.
func (c *decisionCache) highestEpoch() int64 {
	var maxEpoch int64
	for _, e := range c.entries {
		if e.Epoch > maxEpoch {
			maxEpoch = e.Epoch
		}
	}
	return maxEpoch
}

// get returns the entry for key and true, or a zero cacheEntry and false if
// there is none.
//
// Does not check Decision, Epoch, DelegationExpiresAt, or staleness --
// whether a returned entry is still VALID is W3, layered on top by getValid
// below, not this method's own job.
func (c *decisionCache) get(key cacheKey) (cacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.find(key)
}

// maxEpoch is the last epoch this process has observed from the PDP: the
// highest Epoch among the entries. Every entry is stored with the epoch its
// own Decide response carried (storeCacheResult, local_cache.go) and the
// epoch is monotonic (spec V1), so the newest entry already says what the
// PDP last told this process, with no second piece of state to keep in
// sync. Returns 0 for an empty cache, which is inert: an empty cache has no
// entry to compare it against.
func (c *decisionCache) maxEpoch() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.highestEpoch()
}

// errEscalationNotCacheable is put's refusal for an ESCALATE decision --
// spec W4, §4.6: an escalation is a human decision left pending, not a
// verdict the PDP produced, so there is nothing here yet to replay. See the
// package doc's "Validity" section for why this is guarded a second time on
// the read side too (cacheEntryUsable), not trusted to this check alone.
var errEscalationNotCacheable = errors.New("cache: ESCALATE decisions are never cached (spec W4)")

// put upserts entry -- replacing any existing entry with the same key --
// and evicts the oldest entries first if that leaves more than c.max
// (evictOldest).
//
// Refuses outright if entry.Decision is ESCALATE (W4,
// errEscalationNotCacheable) -- the one case where this file inspects
// Decision for a reason other than storing and returning it unchanged.
func (c *decisionCache) put(entry cacheEntry) error {
	if entry.Decision == pdpgrpc.Effect_EFFECT_ESCALATE {
		return errEscalationNotCacheable
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	found := false
	for i := range c.entries {
		if c.entries[i].cacheKey == entry.cacheKey {
			c.entries[i] = entry
			found = true
			break
		}
	}
	if !found {
		c.entries = append(c.entries, entry)
	}
	c.entries = evictOldest(c.entries, c.max)
	return nil
}

// evictOldest keeps at most maxEntries of entries, dropping the
// oldest-by-CachedAt first when there are more. Age is a reasonable proxy
// for "least likely to still be useful": the oldest entry is the first the
// staleness window will retire anyway.
func evictOldest(entries []cacheEntry, maxEntries int) []cacheEntry {
	if len(entries) <= maxEntries {
		return entries
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].CachedAt.Before(entries[j].CachedAt) })
	return entries[len(entries)-maxEntries:]
}

// cacheStalenessWindowEnv is condition 4's one piece of required
// configuration (spec C19): how long a cached decision may keep being
// served without a fresh PDP round trip re-confirming it. No default -- an
// operator states how long an unverifiable decision may keep working, and
// no single value is right for every deployment: too long is too
// permissive (an outage-tolerance feature that quietly becomes a
// revocation-tolerance one), too short is useless (an "outage tolerance"
// that cannot outlast a network blip). Only mcp reads it: hook has no cache
// (package doc, "Memory only") and ignores the variable if it is set.
const cacheStalenessWindowEnv = "STRATIUM_PEP_CACHE_STALENESS_WINDOW"

// cacheConfig is the cache's own configuration. A separate small struct and
// loader, not a field folded into hookConfig: mcp shares hookConfig with
// hook (mcp.go's runMCPCmd), and hook must not require this value.
// combineConfigErrors (mcp.go) composes this loader with mcp's other two.
type cacheConfig struct {
	StalenessWindow time.Duration
}

// loadCacheConfigFromEnv reads cacheConfig from the environment via the
// same requiredEnv/requiredDuration/missingConfigError machinery
// (config.go) every other loader in this binary uses: no default, and a
// missing or non-positive value fails with a message naming it, never a
// guess.
func loadCacheConfigFromEnv() (cacheConfig, error) {
	var missing []string
	raw := requiredEnv(cacheStalenessWindowEnv, &missing)
	if len(missing) > 0 {
		return cacheConfig{}, missingConfigError(missing)
	}
	window, err := requiredDuration(cacheStalenessWindowEnv, raw)
	if err != nil {
		return cacheConfig{}, err
	}
	return cacheConfig{StalenessWindow: window}, nil
}

// epochCurrent is W3's first condition (C20): the epoch entry was computed
// under must equal the last epoch this PEP has itself observed from the
// PDP. lastKnownEpoch is supplied by the caller, not read or tracked here
// -- getValid passes the cache's own maxEpoch.
//
// Equality, not >=: a cached epoch NEWER than what this call site currently
// believes would mean this process itself is behind, which is exactly as
// untrustworthy as being behind the other way around -- W3 asks for the two
// to agree, not merely for the entry to be no older.
func epochCurrent(entry cacheEntry, lastKnownEpoch int64) bool {
	return entry.Epoch == lastKnownEpoch
}

// delegationNotExpired is W3's second condition (C24's time half):
// entry.DelegationExpiresAt, recorded when the entry was cached, must still
// be in the future as of now. This is the reason spec §4.8.1 V2 keeps a
// delegation's own time-based expiry OUT of the revocation epoch:
// expiring is a state change nobody writes -- no row update, no trigger,
// nothing that could ever bump the epoch -- it simply becomes true the
// instant a clock crosses a value nobody had to act on. epochCurrent can
// therefore never catch this on its own; it needs this separate,
// independent time comparison.
func delegationNotExpired(entry cacheEntry, now time.Time) bool {
	return now.Before(entry.DelegationExpiresAt)
}

// tokenNotExpired is W3's third condition (C24's credential half): the
// CALLER's own presented token -- not anything the entry recorded -- must
// not have passed its own "exp" claim as of now. Deliberately independent
// of entry: a hit replays a decision about a delegation, but the credential
// presenting it can have expired on its own schedule since, and only a live
// PDP call can mint a replacement (reissue.go) -- so during an outage an
// expired token must deny even against an otherwise perfect hit, exactly
// the "a cache hit must not extend a credential's life" rule this phase
// states as a global constraint.
//
// Reads the claim, does not verify the signature: jwt.Parser.ParseUnverified's
// own doc warns this is safe only "in cases where you know the signature is
// valid... since it has already been... checked elsewhere in the stack" --
// exactly this system's shape. internal/token's own package doc makes the
// PDP the only verifier (spec K2: no JWKS document, so verification is
// never on the enforcement path for anyone else), so the PEP has never held
// a key to check a signature with, on this path or the ordinary
// forwarded-to-Decide one either. What this narrows is specifically "has
// the claimed expiry passed" -- the same claim, the same trust boundary,
// DelegationExpiresAt is itself sourced from.
//
// Fails closed on anything unreadable: a token that does not even parse,
// and -- easy to miss, see TestTokenNotExpired_MissingExpClaimDenies -- a
// token that parses fine but carries no "exp" claim at all, which
// jwt.MapClaims.GetExpirationTime reports as (nil, nil), NOT an error. A
// check that only looked at the error would treat an unsigned token with no
// expiry as valid forever; checking exp == nil explicitly is what the
// binding "an unparseable expiry... is a miss" rule actually requires here.
func tokenNotExpired(token string, now time.Time) bool {
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(token, claims); err != nil {
		return false
	}
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return false
	}
	return now.Before(exp.Time)
}

// withinStalenessWindow is W3's fourth condition (C19's bound): now must be
// no later than entry.CachedAt plus staleness. Runs from the entry's OWN
// CachedAt rather than the most recent successful PDP contact of any kind
// -- see the package doc's "Validity" section for the choice and its
// justification.
func withinStalenessWindow(entry cacheEntry, now time.Time, staleness time.Duration) bool {
	return !now.After(entry.CachedAt.Add(staleness))
}

// cacheEntryUsable is spec §4.8.2 W3 (all four conditions, all required)
// plus W4 (an ESCALATE is never served, even if one somehow reached the
// cache) -- the one place a caller learns whether a looked-up entry may
// actually be replayed. Go's && already fails closed on the first false the
// same way a hand-written all() would: a single missing or unparseable
// input anywhere in the chain (a zero-value CachedAt, an unparseable token,
// an epoch the caller never actually learned) can only ever push the result
// toward false, never true.
func cacheEntryUsable(entry cacheEntry, lastKnownEpoch int64, token string, now time.Time, staleness time.Duration) bool {
	if entry.Decision == pdpgrpc.Effect_EFFECT_ESCALATE {
		// W4, read side. put already refuses to store one; this is the
		// second half of that same guarantee, in case a future put loses
		// the guard. The failure is silent if missed, so it gets its own
		// line rather than trusting the write-side guard alone.
		return false
	}
	return epochCurrent(entry, lastKnownEpoch) &&
		delegationNotExpired(entry, now) &&
		tokenNotExpired(token, now) &&
		withinStalenessWindow(entry, now, staleness)
}

// getValid is a lookup plus cacheEntryUsable layered on top, judged against
// the cache's own maxEpoch -- the single call a caller needs. A hit that
// fails any condition is indistinguishable from an outright miss, on
// purpose: fail closed means an invalid entry is not a distinct outcome a
// caller could handle specially, it is a miss like any other, and the
// caller falls back to the PDP exactly as it would for a key that was never
// cached at all.
//
// An entry whose Epoch equals maxEpoch is current; one below it was
// computed before a bump this process has since observed through some
// OTHER entry, and misses (C20). An outage stores nothing new and so leaves
// maxEpoch unchanged: existing entries keep serving exactly as long as
// their own staleness window allows.
func (c *decisionCache) getValid(key cacheKey, token string, now time.Time, staleness time.Duration) (cacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.find(key)
	if !ok || !cacheEntryUsable(entry, c.highestEpoch(), token, now, staleness) {
		return cacheEntry{}, false
	}
	return entry, true
}
