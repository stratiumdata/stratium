// Package pdpgrpc: dpop.go is Decide's proof-of-possession gate (spec §4.7.2
// K7). It sits one layer below authenticate.go and answers a strictly
// narrower question: the token said WHICH delegation is calling, and this
// says whether whoever presented it also holds the key that token was bound
// to — for THIS request, once.
//
// # This is a credential check, not a fourth leg
//
// The compound decision is principal ∧ agent ∧ delegation and this task did
// not touch it: internal/authz.FoldVerdicts is unchanged and unreferenced
// here, and nothing below produces a LegResult, a verdict, or an Effect. A
// proof that fails verification denies through denyAndAudit — the same
// pre-decision shape a failed token, a failed catalog load, and a failed
// DeriveTier already share — so it never reaches authz.Decide at all. That is
// the whole reason a fourth leg would be wrong rather than merely redundant:
// a leg is something the three-way AND folds, and a forged credential must
// not be foldable against anything.
//
// # Where each check runs, and why it runs there
//
// Two groups, split by whether the check touches the store.
//
// The LOCAL group — parse, signature, freshness, thumbprint-versus-cnf.jkt,
// htm/htu — runs in matchProof, at Decide's call site immediately after
// authenticateToken and BEFORE loadEpochOrDeny. Every one of them is pure
// computation over bytes already in hand: no I/O, no allocation of anything
// the database knows about. They belong with the token check for the same
// cheapest-first reason the token check belongs ahead of LoadAgent.
//
// The STORE group is one write, SpendProof, and it runs AFTER the epoch read,
// in spendProof below. Two independent arguments land on that placement and
// it is worth recording both, because losing either one would leave the
// ordering looking arbitrary:
//
//   - Spec §4.8.1 V3. The tenant's revocation epoch must be the FIRST store
//     read on this path, so a revocation racing this call can only make the
//     response look older than the state it reflects, never newer
//     (loadEpochOrDeny's own doc comment). SpendProof is a store write.
//     Putting it beside the local checks would put a store call ahead of the
//     epoch and break V3 — TestDecide_EpochIsTheFirstStoreRead asserts
//     exactly that, against the whole of Decide rather than one other read.
//   - The brief's own reason, which is about the jti and not about ordering
//     at all: spend it LAST, after every cheaper check has passed, because
//     spending first means a malformed, stale, or wrong-key proof burns a jti
//     that an honest client might legitimately retry with — turning a garbage
//     request into a denial of service against the client it was aimed at.
//
// Both arguments are satisfied by the same placement, which is why there is
// no tension to resolve here. TestDecide_ProofNotSpentWhenAnEarlierCheckFails
// holds the second one shut, and it asserts SpendProof was never CALLED
// rather than that some later read came back clean — a jti that was never
// written cannot be un-written by a rollback that never happened.
//
// # An unbound token is not an error here
//
// A token with no cnf.jkt is a bearer token, and Decide allows it exactly as
// it did before this phase. That is K5, not an oversight: on the local
// surfaces (hook, mcp) the caller already holds the session file the token
// lives in, so binding buys nothing, and refusing an unbound token in the PDP
// would deny that entire fleet. The refusal belongs at the two network
// surfaces, which is where Tasks 5 and 6 put it — the PDP's job is to report
// what it saw, through DecideResponse.sender_constrained.
package pdpgrpc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/internal/dpop"
	"github.com/stratiumdata/stratium/internal/store"
)

// errNoProof is what matchProof returns when the presented token carries a
// cnf.jkt but the request carries no proof — spec C25's first meaning ("a
// delegation token without a valid DPoP proof is denied when the token is
// sender-constrained"). Named rather than inlined for the same reason
// errNoToken (authenticate.go) is: its text is pinned in one place a test can
// assert against.
//
// Names neither the token nor the thumbprint. The thumbprint is not secret,
// but this error's text becomes the audit chain's Reason (denyAndAudit ->
// DeriveTierDenial), and K10 keeps proof material out of that record; a
// thumbprint would also tell whoever triggered the denial exactly which key
// to go looking for.
// errDelegationBound refuses a token that is not bound to the key recorded
// for its delegation. A delegation is bound to at most one key for its whole
// life (IssueToken and CreateDelegation record it); from that moment its
// earlier bearer token, which nothing else would expire before the
// delegation does, stops working everywhere, and so does a token bound to
// any other key.
var errDelegationBound = errors.New("this delegation is bound to a key and the token presented is not bound to it: " +
	"present the token issued for that key")

// requireDelegationKey returns errDelegationBound when the delegation has a
// recorded key and tokenJKT is not it. tokenJKT is "" for a bearer token.
//
// A token that carries a binding is checked too, not trusted: IssueToken
// only mints one for the recorded key, but a token minted before the key was
// recorded (by an earlier release, which let a delegation take several) can
// name another and stays valid until it expires. A delegation with no
// recorded key accepts any token, bound or not, as before.
func (s *Server) requireDelegationKey(ctx context.Context, delegationID uuid.UUID, tokenJKT string) error {
	// ponytail: one extra read per call. Fold bound_jkt into
	// store.loadDelegationQuery if this shows up in a profile.
	bound, err := s.store.DelegationKey(ctx, delegationID)
	if err != nil {
		return err
	}
	if bound != "" && bound != tokenJKT {
		return errDelegationBound
	}
	return nil
}

var errNoProof = errors.New("token is sender-constrained but the request carried no dpop proof")

// reapSkewMargin is how much longer than strictly necessary a spent-proof row
// is kept, to absorb disagreement between the two clocks that decide its fate.
//
// The two ends of a proof's life are measured on DIFFERENT clocks, and until
// this constant existed they were set to coincide exactly:
//
//   - dpop.Verify refuses a proof once |pdpNow - iat| > window, on this
//     process's Go clock.
//   - store.ReapSpentProofs deletes once expires_at <= NOW(), on the DATABASE
//     clock — deliberately, so every replica sharing one database agrees on
//     the reaping boundary (its own doc comment).
//
// With expires_at set to exactly iat+window, a database clock running δ ahead
// of the PDP's opens a δ-wide band in which a proof still verifies here and
// its row has already been deleted there: replayable. The odds per row are
// roughly δ divided by the reap interval — around 3e-6 at 1ms of skew on the
// default 5m interval — so this is margin, not a live hole. It is also one
// constant, which is cheaper than the arithmetic continuing to assume two
// independent clocks agree to the microsecond.
//
// A minute dominates any skew a deployment sharing an NTP source will see,
// while costing at most one extra minute of rows. Not configuration: an
// operator has no way to measure their PDP-to-database skew and no reason to
// tune this, and the value that matters to them — the freshness window — is
// already configurable. If a deployment ever genuinely needs more, the
// symptom is a replay that should have collided, and the fix is this line.
const reapSkewMargin = time.Minute

// tokenThumbprint reads the RFC 7800 cnf.jkt binding out of a verified
// token's claims, returning "" when the token carries no cnf at all.
//
// Absent is not an error and present-but-unusable is: tokenClaims (token.go)
// writes cnf only for a non-empty thumbprint and never writes an empty one,
// precisely so that "absent means bearer, present means bound" has no third
// state. Anything that verifies under this PDP's own key and still carries a
// malformed cnf did not come from tokenClaims, so it is refused rather than
// silently read as a bearer token — which would be a downgrade a caller could
// aim for if the shape were ever forgeable.
//
// The claim decodes as map[string]any, not map[string]string: it round-trips
// through JSON on the way out of the signer, and encoding/json gives back
// `any` for every member regardless of what tokenClaims put in.
func tokenThumbprint(claims jwt.MapClaims) (string, error) {
	raw, ok := claims[confirmationClaim]
	if !ok {
		return "", nil
	}
	cnf, ok := raw.(map[string]any)
	if !ok {
		return "", fmt.Errorf("token: claim %q is not an object", confirmationClaim)
	}
	jkt, ok := cnf[thumbprintKey].(string)
	if !ok || jkt == "" {
		return "", fmt.Errorf("token: claim %q.%q is missing, not a string, or empty",
			confirmationClaim, thumbprintKey)
	}
	return jkt, nil
}

// matchProof runs every check that can be made without touching the store:
// the proof parses, is signed by the key its own header carries, is fresh
// within the configured window, that key's thumbprint is the one the token
// was bound to, and its htm/htu are the method and URI the enforcement
// surface actually observed.
//
// It returns (nil, nil) — no proof to spend, no failure — in exactly one
// case: the token carries no cnf.jkt. See the package doc for why that is K5
// and not a gap. A proof sent alongside an UNBOUND token is ignored rather
// than verified: it proves possession of a key nothing was bound to, so there
// is no claim it could substantiate and no jti worth spending. It cannot be a
// downgrade either — cnf is covered by the token's signature, so an attacker
// cannot strip it and land here.
//
// # Order within the group is dpop's, and this function has no say in it
//
// Verify enforces RFC 9449 §4.3's own MUSTs (typ, alg, signature, iat), then
// htm/htu, THEN the thumbprint. That is the reverse of the order the task
// brief lists the checks in, and it is not a choice made here: MatchesRequest
// is the only way to reach the thumbprint at all, by construction —
// dpop.Proof keeps jkt/jti/iat unexported and hands them back only in a
// Matched, so "verify a proof, bind the key, and never check it was made for
// this request" does not compile. There is no ordering left to choose.
//
// A reader who finds this comment claiming the opposite and "corrects" the
// code will find it does not build, and the obvious way to make it build is
// to export jkt from dpop.Proof — which would undo the compile-time
// unskippability that design exists to provide. Do not. The consequence of
// the order is only which mismatch gets NAMED when a proof is both
// wrong-key and wrong-request: htm/htu wins, and both deny either way.
func (s *Server) matchProof(req *DecideRequest, jkt string, now time.Time) (*dpop.Matched, error) {
	if jkt == "" {
		return nil, nil
	}
	if req.GetDpopProof() == "" {
		return nil, errNoProof
	}

	proof, err := dpop.Verify(req.GetDpopProof(), now, s.cfg.DPoPFreshnessWindow)
	if err != nil {
		return nil, err
	}
	matched, err := proof.MatchesRequest(req.GetObservedMethod(), req.GetObservedUri())
	if err != nil {
		return nil, err
	}
	// AFTER MatchesRequest because matched is where the thumbprint comes
	// from — there is no earlier point at which it exists (see this
	// function's own doc comment). The comparison is exact: a thumbprint is a
	// base64url SHA-256 digest, so there is nothing to normalize and any
	// tolerance at all would be a way in.
	if matched.JKT != jkt {
		// Neither value is echoed. Both are thumbprints rather than secrets,
		// but this text lands in the audit chain via DeriveTierDenial, where
		// K10 wants no proof material, and telling a caller which key WOULD
		// have worked is free reconnaissance for one that guessed wrong.
		return nil, errors.New("dpop: proof key does not match the token's cnf.jkt binding")
	}
	return &matched, nil
}

// spendProof records matched.JTI as spent, denying a replay (spec §4.7.2 K8).
// The one store call this file makes, and Decide invokes it only after
// loadEpochOrDeny — see the package doc for the two independent reasons that
// is where it goes.
//
// # The expiry this computes is the whole of the reaper's correctness
//
// store.SpendProof does not and cannot validate expiresAt: it has no clock
// and no window, so it cannot tell a legitimately short expiry from a broken
// one (Task 3 recorded that deliberately). A writer that passed the zero
// time, or now, or any already-past instant would compile, insert cleanly,
// and make EVERY row reapable on the very next sweep — replay prevention
// would silently stop working while the reaper's count looked healthy and the
// table looked reassuringly small. So the value is computed here, once, and
// pinned by a test rather than by this paragraph:
// TestDecide_SpendsTheProofWithAnExpiryOfIATPlusTheWindow asserts the exact
// instant, not merely that it is in the future.
//
// iat plus the window, not now plus the window: past that instant
// dpop.Verify refuses this proof for staleness whether or not the table still
// remembers it, so a row living much longer protects nothing, and one living
// any shorter leaves a gap in which the same proof both verifies and no
// longer collides. matched.IssuedAt is the proof's own iat, already checked
// against this same window by Verify, so it cannot be arbitrarily far in the
// past.
//
// Plus reapSkewMargin, because "that instant" is measured on two different
// clocks — this process's for freshness, the database's for reaping — and
// setting them to coincide exactly assumes the two agree to the microsecond.
// See that constant for the band this closes.
//
// A failed write DENIES, and the two failure kinds stay distinguishable in
// the denial's own text: store.ErrProofSpent is a replay (an attack signature
// or a broken client re-sending a proof it must mint fresh), anything else is
// the database. Both deny — a replay check that fails open is not a replay
// check, exactly as a failed audit write denies (D3) — but an operator
// watching a spike of denials needs to know which one they are looking at.
func (s *Server) spendProof(ctx context.Context, matched dpop.Matched) error {
	expiresAt := matched.IssuedAt.Add(s.cfg.DPoPFreshnessWindow + reapSkewMargin)
	if err := s.store.SpendProof(ctx, matched.JTI, expiresAt); err != nil {
		if errors.Is(err, store.ErrProofSpent) {
			// store's own text, unwrapped and un-decorated: it already reads
			// as "dpop proof already spent" and deliberately carries no jti
			// (K10). Wrapping it would only bury that in a second layer of
			// prefix by the time it reaches the audit chain's Reason.
			return err
		}
		return fmt.Errorf("dpop: spend proof: %w", err)
	}
	return nil
}
