// Token issuance: CreateDelegation (delegation.go) mints a token alongside
// every new delegation, and IssueToken (below) re-issues one for a
// delegation whose own token has expired. Both funnel through mintToken so
// the claim set and the expiry clamp are each defined exactly once.
package pdpgrpc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"stratium/internal/store"
)

// Claim keys for every token this package signs. Named constants, not
// string literals scattered across tokenClaims/tests: the "assert the token
// carries no scope fields" test (token_test.go) diffs a decoded token's key
// set against exactly this set, and a typo in a literal repeated at both
// call sites could silently pass a test that meant to catch it.
//
// sub/iat/exp/jti are the four registered JWT claims (RFC 7519 §4.1) that
// fit what a delegation reference needs; tenantIDClaim is this system's own
// addition, since JWT has no registered claim for a multi-tenant boundary.
// exp is required, not merely conventional here — internal/token.Verify
// calls jwt.WithExpirationRequired(), so a token minted without it would
// fail to verify at all, at every future call, not just fail to expire.
const (
	subjectClaim  = "sub"       // the delegation this token names (models.Delegation.ID)
	tenantIDClaim = "tenant_id" // the tenant the delegation belongs to
	issuedAtClaim = "iat"
	expiryClaim   = "exp"
	tokenIDClaim  = "jti" // unique per issuance, including a re-issuance naming the same delegation
)

// tokenClaims builds the claim set for a token naming delegationID: the
// minimum that identifies it, and nothing more (spec §4.7.1 K3). Deliberately
// excludes every scope field — max_action_tier, approved_tools,
// classification_caps, resource_constraints — even though both callers below
// already have all of them in hand at the point they call this. Baking any
// of them in would give the token its own copy of the delegation's
// authority, one that would go stale the instant the row is revoked or
// narrowed: K3's whole point is that verifying a token means loading the
// delegation it names and asking the row, never reading an answer the token
// cached at mint time. Nothing here should grow a new field without
// re-reading K3 first — see TestTokenClaims_CarriesNoScopeFields, which
// exists specifically to make that mistake fail loudly instead of silently.
func tokenClaims(delegationID uuid.UUID, tenantID string, issuedAt, expiresAt time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		subjectClaim:  delegationID.String(),
		tenantIDClaim: tenantID,
		issuedAtClaim: issuedAt.Unix(),
		expiryClaim:   expiresAt.Unix(),
		tokenIDClaim:  uuid.New().String(),
	}
}

// clampTokenExpiry returns the earlier of requested and delegationExpiresAt,
// and whether requested had to be reduced to reach it. A token's lifetime is
// never longer than the delegation it names (spec §4.7.1): a credential that
// could outlive the authority it references would keep authenticating after
// that authority ended, which is exactly the staleness K3 exists to rule
// out. Equal counts as NOT clamped — CreateDelegation calls this with
// requested == delegationExpiresAt exactly (a fresh token has no
// independently requested lifetime; see mintToken's callers), and that
// ordinary case must not report itself as having been cut short.
func clampTokenExpiry(requested, delegationExpiresAt time.Time) (expiry time.Time, clamped bool) {
	if requested.After(delegationExpiresAt) {
		return delegationExpiresAt, true
	}
	return requested, false
}

// mintToken signs a fresh token naming delegationID, after clamping
// requestedExpiry to delegationExpiresAt. The only two callers —
// CreateDelegation and IssueToken — are also the only two places this
// system mints a token at all, so the claim set and the clamp can only ever
// be defined once, here, rather than risk drifting between two hand-written
// copies.
//
// A signing failure returns an error and nothing else: neither caller may
// hand a delegation id to a caller without a token to go with it (see
// CreateDelegationResponse.token's own doc comment in the proto) — fail
// closed applies to "could not mint a credential" exactly as it does to
// every other failure mode this package fails closed on.
func (s *Server) mintToken(
	delegationID uuid.UUID, tenantID string, now, requestedExpiry, delegationExpiresAt time.Time,
) (token string, expiry time.Time, clamped bool, err error) {
	expiry, clamped = clampTokenExpiry(requestedExpiry, delegationExpiresAt)
	claims := tokenClaims(delegationID, tenantID, now, expiry)
	token, err = s.signer.Sign(claims)
	if err != nil {
		// err is wrapped, never the claims or the (empty, on this path)
		// token string: a signing failure is exactly the kind of thing
		// that must never put a token or key material into a log line or
		// an error message a caller might surface — see the phase's
		// global "never log a token, a key, or a key path's contents"
		// constraint. There is no token yet to leak on this path, and
		// nothing below ever formats one either.
		return "", time.Time{}, false, fmt.Errorf("sign token: %w", err)
	}
	return token, expiry, clamped, nil
}

// IssueToken re-issues a token for delegationID — re-issuance, not re-grant:
// scope was already decided once, by CreateDelegation, and this method
// touches none of it.
//
// Order: validate the request -> load the delegation FRESH from this
// tenant -> refuse if it is revoked or expired -> mint. The load is not
// optional and not a formality: it is the one thing that makes re-issuance
// different from a caller minting its own token. A version of this method
// that trusted delegation_id and skipped the load would let a revoked or
// expired delegation's holder mint itself an unlimited stream of fresh,
// perfectly valid-looking tokens forever — exactly the bare-id trust spec
// K4 removes from Decide, reintroduced one RPC over. Loading it fresh, on
// this call, from this tenant's own row (RLS — no WHERE tenant_id, see the
// package doc) is what re-earns the check CreateDelegation's own audit
// already recorded once and IssueToken cannot simply assume still holds.
func (s *Server) IssueToken(ctx context.Context, req *IssueTokenRequest) (*IssueTokenResponse, error) {
	id, err := parseNonNilUUID(req.GetDelegationId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "delegation_id: %s", err)
	}
	if req.GetTtlSeconds() <= 0 {
		return nil, status.Error(codes.InvalidArgument, "ttl_seconds must be positive")
	}

	d, err := s.store.LoadDelegation(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Covers both "no such delegation" and "this delegation belongs
			// to another tenant" identically — RLS makes the two
			// indistinguishable by design (store's own package doc), and
			// this is not a place that gets to be an exception to that.
			return nil, status.Errorf(codes.NotFound, "delegation %s: %s", id, err)
		}
		return nil, status.Errorf(codes.Internal, "load delegation: %s", err)
	}

	// Revoked is checked before expiry, matching DelegationLeg's own
	// ordering (internal/authz/delegation.go) for the same reason: both
	// conditions independently deny, but naming which one happened is more
	// actionable for whoever reads the error than a single collapsed
	// "not alive" would be.
	if d.Revoked {
		return nil, status.Errorf(codes.PermissionDenied, "delegation %s is revoked", id)
	}
	now := time.Now()
	if !d.IsActive(now) {
		// d.Revoked is already excluded above, so IsActive returning false
		// here can only mean expired — reusing models.Delegation.IsActive
		// rather than re-deriving "now.After(d.ExpiresAt)" locally, the
		// same expiry test DelegationLeg itself trusts.
		return nil, status.Errorf(codes.PermissionDenied,
			"delegation %s expired at %s", id, d.ExpiresAt.Format(time.RFC3339))
	}

	requested := now.Add(time.Duration(req.GetTtlSeconds()) * time.Second)
	tok, expiry, clamped, err := s.mintToken(d.ID, s.cfg.TenantID, now, requested, d.ExpiresAt)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "sign token: %s", err)
	}

	return &IssueTokenResponse{
		Token:                     tok,
		ExpiresAt:                 timestamppb.New(expiry),
		ClampedToDelegationExpiry: clamped,
	}, nil
}
