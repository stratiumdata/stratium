// local_cache.go is the logic mcp_authorize.go's decideAndRelay calls to
// consult and populate the decision cache (cache.go) -- and its ONLY caller.
// hook has no cache: it is a new process per tool call, and the cache lives
// only in process memory (cache.go's package doc, "Memory only"), so a hook
// would have nothing to consult. extauthz and proxy always call the PDP and
// never touch this file's functions (spec §4.8.3 W6).
//
// WHY MEMORY ONLY. A cache hit is defined by NOT calling the PDP, and the
// PDP is the only component that ever verifies a token's signature (K2) --
// this binary reads a token with jwt.ParseUnverified. A hit therefore
// replays a verdict with nothing re-checking it, which is only sound if the
// entry itself is known to have come from the PDP. The one place that holds
// is this process's own memory: every entry in a decisionCache was put
// there by storeCacheResult, from a Decide response this process received.
// Nothing this binary can read from disk carries that guarantee, so no
// decision is ever read from disk.
//
// WHY extauthz AND proxy STAY OUT, STRUCTURALLY. consultCache requires sess
// *pdpgrpc.CreateDelegationResponse -- the exact value loadSessionFile
// (session_file.go) returns -- as its source of the delegation id and token
// a lookup needs. That is deliberately not a bare (token, id) pair, which
// any caller could assemble from anything. extauthz.go and proxy.go have no
// session file (see their own "NO SESSION FILE" sections): their caller IS
// the party being policed and presents its own token on every call, so a
// forged token -- arbitrary signature bytes, claims naming a known
// delegation and a far-future expiry -- would decode cleanly, build a cache
// key, satisfy every W3 condition, and be served a cached ALLOW with the
// PDP never contacted. A future reader wiring the cache into either would
// hit a compile error reaching for a value that does not exist in scope.
//
// WHERE THE EPOCH COMES FROM. The epoch an entry is judged against is the
// cache's own maxEpoch (cache.go), never sess.GetEpoch(): the session
// file's epoch is a snapshot written once, at session-start, while each
// entry carries the epoch of its own live Decide response. Comparing the
// two would fail every entry permanently the first time any control-plane
// write anywhere in the tenant bumped the epoch.
//
// WHY AN ESCALATION IS NEVER CACHED, EVEN RESOLVED. W4 says an ESCALATE
// decision is never cached; cache.go's put and cacheEntryUsable each
// enforce the literal rule, on the write and read side. storeCacheResult's
// own check below runs before either. decideAndRelay calls storeCacheResult
// exactly once, UNCONDITIONALLY, with no second matching check at the call
// site.
//
// This file goes one step stricter than W4's literal text, by construction:
// that one storeCacheResult call sits ONLY on the response that settles
// BEFORE any escalation wait begins (the ordinary Decide call, or a reissue
// retry) -- never on resolveApproval's own post-approval retry response,
// even though that response is itself ALLOW or DENY. A human approving one
// specific pending action is not the PDP producing a general, replayable
// verdict about every future identical call -- caching that outcome would
// let a LATER, superficially identical call skip the human step the first
// one required.
package main

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/stratiumdata/stratium/internal/pdpgrpc"
)

// cacheHitDenyReason is served for every cache-hit DENY. Never the original PDP's own reason text:
// cache.go's cacheEntry deliberately never stores Reason at all --
// this project's own binding "never log a cached decision's reason" rule --
// so there is nothing to reproduce even if this text wanted to. Labelling
// the denial as cache-served, explicitly, is what keeps it from being
// mistaken for a fresh policy verdict this process just computed (it did
// not -- it replayed one, per this project's own "classifies nothing,
// decides nothing" rule) or for silence about why no specific reason
// follows.
const cacheHitDenyReason = "stratium-pep: cached decision: this exact request was denied " +
	"(served from cache, without contacting the PDP; the cache does not retain the original policy reason text)"

// cacheMissUnreachableReason wraps describeRPCError's own text (hook.go)
// with the one fact unique to the cache-wired surface: this denial follows
// a cache MISS, not merely a failed RPC. Applied uniformly to every
// describeRPCError outcome: whichever way the call failed, "there was no
// cached fallback for this request" is equally true and equally worth an
// operator knowing. hook does not use this -- it has no cache to miss.
func cacheMissUnreachableReason(rpcErr string) string {
	return fmt.Sprintf("stratium-pep: no cached decision for this request, and %s", rpcErr)
}

// cacheKeyFor builds the W2 key for one Decide call: (delegation id, tool,
// input digest). InputDigest reuses sha256.Sum256(rawInput) -- the exact
// digest internal/pdpgrpc/server.go's appendAudit already computes for the
// audit chain (cache.go's own doc comment) -- not a second notion of request
// identity.
func cacheKeyFor(delegationID, tool, rawInput string) cacheKey {
	return cacheKey{DelegationID: delegationID, Tool: tool, InputDigest: sha256.Sum256([]byte(rawInput))}
}

// consultCache is the one cache READ this binary ever performs -- see this
// file's own package doc for why its signature is what keeps extauthz.go and
// proxy.go from being able to call it by accident.
//
// token is sess.GetToken(): condition 3 (cache.go's tokenNotExpired) is
// specifically about the CALLER'S OWN currently-presented credential, which
// only the session file can supply, re-read fresh on every call
// (mcp_authorize.go's own doc comment on decideAndRelay).
func consultCache(cache *decisionCache, staleness time.Duration, sess *pdpgrpc.CreateDelegationResponse, tool, rawInput string, now time.Time) (cacheEntry, bool) {
	return cache.getValid(cacheKeyFor(sess.GetDelegationId(), tool, rawInput), sess.GetToken(), now, staleness)
}

// storeCacheResult is the one cache WRITE this binary ever performs, called
// by decideAndRelay UNCONDITIONALLY, immediately after a Decide call (or a
// reissue retry) settles on a final response -- see the package doc's "WHY
// AN ESCALATION IS NEVER CACHED, EVEN RESOLVED."
//
// token is the credential that ACTUALLY produced resp -- req.Token at the
// point resp was obtained, which reissueAndRetryDecide (reissue.go) may have
// mutated in place to a freshly re-issued token -- never sess.GetToken(),
// which stays the session file's original, possibly-stale value across a
// reissue. Sourcing DelegationExpiresAt from the wrong one would record an
// expiry for a token that was never the one actually verified for this
// decision.
func storeCacheResult(cache *decisionCache, delegationID, tool, rawInput, token string, resp *pdpgrpc.DecideResponse, now time.Time) {
	if resp.GetEffect() == pdpgrpc.Effect_EFFECT_ESCALATE {
		return
	}
	expiresAt, ok := tokenExpiry(token)
	if !ok {
		// The token that just produced a live PDP verdict does not itself
		// decode a usable expiry -- reachable only if authentication failed
		// server-side before Decide ever reached the epoch read (epoch_test.go's
		// TestDecide_AuthFailure_LeavesEpochUnset is the server-side proof this
		// case exists at all). There is no trustworthy DelegationExpiresAt to
		// record here, and W3's delegationNotExpired already fails closed on a
		// zero time.Time regardless (now.Before a zero value is false for any
		// real now, so such an entry could never be served even if written) --
		// skipping the write outright simply avoids spending a cache slot on an
		// entry that could never be a hit.
		return
	}
	entry := cacheEntry{
		cacheKey:            cacheKeyFor(delegationID, tool, rawInput),
		Decision:            resp.GetEffect(),
		Epoch:               resp.GetEpoch(),
		DelegationExpiresAt: expiresAt,
		CachedAt:            now,
	}
	// put's only error is the ESCALATE refusal, already ruled out above.
	_ = cache.put(entry)
}

// tokenExpiry decodes token's own "exp" claim without verifying its
// signature -- the same unverified read cache.go's tokenNotExpired performs
// on the read side, for the identical reason: spec K2 makes the PDP the sole
// verifier, so the PEP has never held a key to check one with, on this path
// or the ordinary forwarded-to-Decide one either. Neither DecideResponse nor
// CreateDelegationResponse carries a delegation-expiry field:
// pdp.proto's CreateDelegationResponse.token comment states a delegation's
// expiry IS its token's own exp claim, not a second copy this function could
// read from anywhere else.
func tokenExpiry(token string) (time.Time, bool) {
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(token, claims); err != nil {
		return time.Time{}, false
	}
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return time.Time{}, false
	}
	return exp.Time, true
}
