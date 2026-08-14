// local_cache.go is the shared logic hook.go's runHook and mcp_authorize.go's
// decideAndRelay both call to consult and populate the decision cache
// (cache.go, Phase 13 Tasks 1-2) -- and the ONLY two callers, by spec §4.8.3
// W6: extauthz and proxy always call the PDP and never touch this file's own
// functions.
//
// THE BOUNDARY IS STRUCTURAL, NOT A COMMENT. consultCache and
// storeCacheResult both require sess *pdpgrpc.CreateDelegationResponse -- the
// exact value loadSessionFile (session_file.go) returns -- as their one
// caller-supplied source of the delegation id, epoch, and token a cache
// operation needs. That is deliberately not a bare (epoch, token, id) tuple,
// which any caller could assemble from anything: hook.go and mcp_authorize.go
// both already hold a real *pdpgrpc.CreateDelegationResponse because both
// already call loadSessionFile for unrelated reasons of their own (K4 --
// authenticating the call at all). extauthz.go and proxy.go structurally do
// not, and never have -- see extauthz.go's own "NO SESSION FILE" section and
// proxy.go's identical one, both there specifically because those surfaces'
// caller IS the party being policed and must re-authenticate on every call
// (W6, and A10 one layer up). A future reader wiring the cache into either
// would hit a compile error reaching for a value that does not exist in
// scope, before writing a single line of cache-consulting logic -- getting
// one means first undoing "NO SESSION FILE" as a deliberate property those
// files state at length, not a line that merely happens to compile by
// passing something else in its place. This follows the precedent
// escalation.go's own doc comment sets for resolveApproval's signature: a
// hookConfig value "populated with only the fields this function actually
// reads" would be "a lie wearing hookConfig's name" that compiles but
// misleads; a signature that only accepts the real thing is what keeps a
// caller honest, here as there.
//
// WHY THE BOUNDARY MATTERS (restated from spec §4.8.3, cache.go's own
// package doc, and this project's git history -- see the plan's own "W6
// RULING" entry for the full account): a cache hit is defined by NOT calling
// the PDP, and the PDP is the only component that ever verifies a token's
// signature (K2) -- this binary reads a token with jwt.ParseUnverified,
// which cache.go's tokenNotExpired already does deliberately, on the
// strength of a signature "already... checked elsewhere in the stack." A hit
// removes the only place that check ever happens. On hook and mcp the caller
// is local and already holds the session file containing a REAL token, so
// serving from cache grants it nothing it did not already have. On extauthz
// and proxy the caller IS the party being policed, so a forged token --
// arbitrary signature bytes, claims naming a known delegation and a
// far-future expiry -- would decode cleanly, build a cache key, satisfy
// every W3 condition, and be served a cached ALLOW with the PDP never
// contacted.
//
// WHERE THE CACHE FILE LIVES. cacheFilePathFor derives the cache's own path
// from SessionFilePath -- a fixed suffix, in the same directory -- rather
// than a second, independently configured env var: W5 already pins the
// cache "on disk, beside the session file, with the same integrity
// posture," a fixed relationship to the one path an operator already
// configures, not a second location that could be pointed elsewhere by
// mistake or left unset entirely for a location the spec does not leave
// open to configure at all.
//
// WHY AN ESCALATION IS NEVER CACHED, EVEN RESOLVED. W4 says an ESCALATE
// decision is never cached; cache.go's cachePut and cacheEntryUsable each
// already enforce the literal rule independently, on the write and read side
// (its own package doc, "Validity") -- storeCacheResult's own check below,
// which runs before either of those, is what keeps this file's one call to
// cachePut from ever reaching a cache.go layer at all for that response,
// rather than trusting cachePut's refusal alone. Both runHook and
// decideAndRelay call storeCacheResult exactly once, UNCONDITIONALLY --
// there is no second, matching check at either call site, deliberately: a
// second identical check there would guard nothing storeCacheResult does
// not already guard for the SAME two callers, which is a different shape of
// redundancy than cache.go's own two guards (those protect genuinely
// different paths -- a write cachePut itself performs, and a read of a file
// that could hold an ESCALATE entry by some route OTHER than cachePut, e.g.
// hand-edited -- see cache.go's own doc comment).
//
// This file goes one step stricter than W4's literal text, by construction:
// both callers place their one storeCacheResult call ONLY on the response
// that settles BEFORE any escalation wait begins (the ordinary Decide call,
// or a reissue retry) -- never on resolveApproval's own post-approval retry
// response, even though that response is itself ALLOW or DENY, never
// ESCALATE (resolveApproval's own doc comment). That stricter property is
// NOT enforced by checking resp's effect at all -- it holds because there is
// only one storeCacheResult call site in either function, positioned before
// the switch that would otherwise reach awaitApproval/resolveApproval, and
// no second call after either returns. A human approving one specific
// pending action is not the PDP producing a general, replayable verdict
// about every future identical call -- caching that outcome would let a
// LATER, superficially identical call skip the human step the first one
// required, which is exactly the "serves an approval that was never
// granted" failure W4 names, just reached one step later than the literal
// ESCALATE value.
package main

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"stratium/internal/pdpgrpc"
)

// cacheFilePathFor derives the decision cache's own file path from the
// session file it sits beside -- see this file's own package doc, "WHERE THE
// CACHE FILE LIVES."
func cacheFilePathFor(sessionFilePath string) string {
	return sessionFilePath + ".cache.json"
}

// cacheHitDenyReason is served for every cache-hit DENY, on both surfaces
// this file wires the cache into. Never the original PDP's own reason text:
// cache.go's cacheEntry (Task 1) deliberately never stores Reason at all --
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
// with the one fact unique to a cache-wired surface: this denial follows a
// cache MISS, not merely a failed RPC. Applied uniformly to every describeRPCError
// outcome (Unavailable, DeadlineExceeded, NotFound, or a generic application
// error), not only the literally-unreachable case: whichever way the call
// then failed, "there was no cached fallback for this request" is equally
// true and equally worth an operator knowing before they start debugging a
// specific RPC failure mode. An operator debugging an outage needs to tell
// this apart from an ordinary policy denial (the PDP's own reason, passed
// through unprefixed elsewhere in both callers) -- the task brief's own
// requirement -- and this prefix is what makes that distinction legible at a
// glance rather than requiring the reader to already know the cache exists.
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
// lastKnownEpoch is sess.GetEpoch() and token is sess.GetToken(): both are
// exactly what cacheGetValid's own doc comment (cache.go) asks each Task 3
// surface to supply from "the epoch on its own most recent
// Decide/CreateDelegation/IssueToken response." For hook, a fresh subprocess
// with no memory between calls, and for mcp, which re-reads the session file
// fresh on every call for the identical revocation-latency reason hook does
// (mcp_authorize.go's own doc comment on decideAndRelay), the session file
// IS that response -- the freshest one this process has ever independently
// observed, since neither surface tracks a fresher epoch anywhere else (see
// the package doc's note on why deliberately not: a second, in-memory-only
// epoch tracker would be a second piece of state every call site has to
// remember to update correctly, the same shared-state risk cache.go's own
// package doc already rejected once for staleness).
func consultCache(cachePath string, staleness time.Duration, sess *pdpgrpc.CreateDelegationResponse, tool, rawInput string, now time.Time) (cacheEntry, bool) {
	key := cacheKeyFor(sess.GetDelegationId(), tool, rawInput)
	return cacheGetValid(cachePath, key, sess.GetEpoch(), sess.GetToken(), now, staleness)
}

// storeCacheResult is the one cache WRITE this binary ever performs, called
// by both runHook and decideAndRelay UNCONDITIONALLY, immediately after a
// Decide call (or a reissue retry) settles on a final response -- see the
// package doc's "WHY AN ESCALATION IS NEVER CACHED, EVEN RESOLVED" for why
// neither caller needs its own matching check before calling this function:
// the ESCALATE check below is the one and only place W4's literal "never
// cache an ESCALATE" rule is enforced for a response this file ever
// receives, and a caller-side copy of it would guard nothing this one does
// not already guard for the same two call sites.
//
// token is the credential that ACTUALLY produced resp -- req.Token at the
// point resp was obtained, which reissueAndRetryDecide (reissue.go) may have
// mutated in place to a freshly re-issued token -- never sess.GetToken(),
// which stays the session file's original, possibly-stale value across a
// reissue. Sourcing DelegationExpiresAt from the wrong one would record an
// expiry for a token that was never the one actually verified for this
// decision.
//
// A write failure is silently discarded, the same "best-effort, not
// reported anywhere" treatment mcp_authorize.go's forward already gives an
// unwritable destination: the cache is an optimization a caller can always
// fall back from (cacheGet's own doc comment, cache.go), and this call sits
// after the real decision has already been made -- a failure here can only
// cost a future call its chance at a hit, never change what this call
// itself reports.
func storeCacheResult(cachePath, delegationID, tool, rawInput, token string, resp *pdpgrpc.DecideResponse, now time.Time) {
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
	_ = cachePut(cachePath, entry)
}

// tokenExpiry decodes token's own "exp" claim without verifying its
// signature -- the same unverified read cache.go's tokenNotExpired performs
// on the read side, for the identical reason: spec K2 makes the PDP the sole
// verifier, so the PEP has never held a key to check one with, on this path
// or the ordinary forwarded-to-Decide one either. This resolves Task 1's own
// flagged concern (neither DecideResponse nor CreateDelegationResponse
// carries a delegation-expiry field) exactly as the plan predicted:
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
