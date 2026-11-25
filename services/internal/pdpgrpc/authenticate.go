// Package pdpgrpc: authenticate.go is Decide's authentication gate (spec
// §4.7.1 K4). It is the one place a caller-presented token becomes a
// delegation id Decide may go on to load and evaluate, or a reason to deny
// before anything else — agent lookup, chain load, tier derivation — ever
// runs.
//
// See escalation.go's own doc comment for the shape this mirrors: an
// approval is a fourth condition layered on top of a fresh three-leg
// evaluation, never a bypass of it. A token is the same shape one layer
// earlier — it answers "how did the caller identify itself," never "is the
// action allowed" (K3). authenticateToken proves only the former; Decide
// still runs the delegation this returns through the exact same load and
// three-leg evaluation a bare id would have, so a revoked or expired
// delegation denies there, not here (see Decide's own comment at the call
// site).
package pdpgrpc

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// errNoToken is what authenticateToken returns when DecideRequest.token is
// empty. Named rather than inlined so its text is pinned in exactly one
// place a test can assert against — the same reason errZeroUUID (server.go)
// is its own variable rather than a literal repeated at every zero-UUID
// rejection. K4 is explicit that this is a denial like any other token
// failure, never a fallback to a bare id: there is no second field left on
// DecideRequest for an absent token to fall back to.
var errNoToken = errors.New("no token provided")

// authenticateToken verifies token and returns the delegation id it names,
// plus the key thumbprint it was bound to ("" for a bearer token). This is
// Decide's ONLY gate on who is calling. An absent, malformed, expired, or
// wrongly-signed token returns the zero UUID and a non-nil error; Decide's
// own call site denies on that error without ever loading an agent or a
// delegation chain — see Decide's own comment for why that ordering
// (authenticate first, cheapest and no store I/O, before either lookup) is
// deliberate.
//
// The thumbprint comes back from here rather than from a second decode of
// the same token in dpop.go: the claims are already parsed and, more to the
// point, already VERIFIED at this line. A cnf.jkt read off an unverified
// token would be a binding an attacker could choose.
//
// A token that verifies buys authentication only, never authorization (K3):
// the id returned here is not trusted for anything beyond "load this row
// and evaluate it exactly as every other call does." The caller of this
// method still runs all three legs against whatever that load finds,
// including a since-revoked or since-expired row — this function has no
// opinion on that row at all, because it never reads one; it only reads the
// token.
//
// Never logs tokenString or any claim decoded from it, on any path,
// including the errors returned here — see the phase's "never log a token
// or key material" constraint. internal/token.Verify's own errors already
// name the failure kind (expired, signature invalid, malformed) without
// echoing the token or the key, and this function's own errors about a bad
// "sub" claim name only the claim's key, never a value decoded from the
// token.
func (s *Server) authenticateToken(tokenString string) (uuid.UUID, string, error) {
	if tokenString == "" {
		return uuid.Nil, "", errNoToken
	}

	if err := overLong(bounded{"token", tokenString, s.cfg.Limits.CredentialBytes}); err != nil {
		return uuid.Nil, "", err
	}

	claims, err := s.signer.Verify(tokenString)
	if err != nil {
		return uuid.Nil, "", err
	}

	// claims is otherwise unvalidated by internal/token.Verify — that
	// package's own doc comment is explicit that claims policy belongs to
	// whoever defines the claims, not to it. subjectClaim is this system's
	// own claim (tokenClaims, token.go), and a token that verifies
	// cryptographically but does not carry a well-formed one is exactly as
	// unusable here as a token that never verified at all: either way there
	// is no delegation id to load.
	//
	// tenant_id (also stamped by tokenClaims) is deliberately NOT read or
	// compared here, even though every token this system issues carries
	// one: the tenant boundary is RLS's job everywhere else in this
	// codebase (store.go's own package doc), and a token naming another
	// tenant's delegation must surface as NotFound from the LoadChain call
	// Decide makes next — not as a verification failure here. Comparing
	// against s.cfg.TenantID at this layer would be exactly the second,
	// divergent tenant check store.go's doc comment warns against: one
	// Go-level, one RLS-level, free to silently disagree.
	sub, ok := claims[subjectClaim].(string)
	if !ok {
		return uuid.Nil, "", fmt.Errorf("token: claim %q is missing or not a string", subjectClaim)
	}
	delegationID, err := parseNonNilUUID(sub)
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("token: claim %q: %w", subjectClaim, err)
	}
	jkt, err := tokenThumbprint(claims)
	if err != nil {
		return uuid.Nil, "", err
	}
	return delegationID, jkt, nil
}
