package pdpgrpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"

	"github.com/stratiumdata/stratium/internal/dpop"
	"github.com/stratiumdata/stratium/internal/token"
)

// priorToken mints the token a re-issue request presents: one this signer
// issued for delegationID, already EXPIRED, since replacing an expired token
// is the ordinary reason to call IssueToken at all. jkt binds it ("" for a
// bearer token).
func priorToken(t *testing.T, signer TokenSigner, delegationID uuid.UUID, jkt string) string {
	t.Helper()
	now := time.Now()
	tok, err := signer.Sign(tokenClaims(delegationID, testTenant, jkt, now.Add(-2*time.Hour), now.Add(-time.Hour)))
	if err != nil {
		t.Fatalf("priorToken: %v", err)
	}
	return tok
}

// freshJWK returns a new P-256 public key as a JWK document and its RFC 7638
// thumbprint, computed by the same dpop.Thumbprint the server uses.
func freshJWK(t *testing.T) (jwk, jkt string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b := func(v []byte) string { return base64.RawURLEncoding.EncodeToString(v) }
	x, y := key.X.FillBytes(make([]byte, 32)), key.Y.FillBytes(make([]byte, 32)) //nolint:staticcheck // test key material
	jwk = fmt.Sprintf(`{"kty":"EC","crv":"P-256","x":%q,"y":%q}`, b(x), b(y))
	jkt, err = dpop.Thumbprint([]byte(jwk))
	if err != nil {
		t.Fatalf("freshJWK thumbprint: %v", err)
	}
	return jwk, jkt
}

func strangerSigner(t *testing.T) *token.Signer {
	t.Helper()
	s, err := token.Load(freshECKeyPEM(t), "")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A delegation id is not a secret, so it must never be enough on its own to
// mint a credential. The caller has to present a token this PDP issued for
// the same delegation.
func TestIssueToken_RequiresAPriorTokenForTheSameDelegation(t *testing.T) {
	signer := testSigner(t)
	delegationID := uuid.New()

	tests := []struct {
		name  string
		token string
		want  codes.Code
	}{
		{"no token: a bare delegation id", "", codes.Unauthenticated},
		{"not a token", "not-a-jwt", codes.Unauthenticated},
		{"signed by another key", priorToken(t, strangerSigner(t), delegationID, ""), codes.Unauthenticated},
		{"a real token for a different delegation", priorToken(t, signer, uuid.New(), ""), codes.PermissionDenied},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := &fakeStore{delegation: activeDelegation(delegationID, time.Now())}
			resp, err := NewServer(fs, denyAllPolicy(), testConfig(), signer).IssueToken(context.Background(),
				&IssueTokenRequest{DelegationId: delegationID.String(), TtlSeconds: 600, Token: tt.token})
			if resp != nil {
				t.Fatalf("IssueToken() minted a token: %+v", resp)
			}
			wantCode(t, err, tt.want)
		})
	}
}

// Expiry is the one thing not checked on the prior token: replacing an
// expired token is the point. The delegation's own state still gates it
// (TestIssueToken_RevokedDelegation_PermissionDenied and its neighbours).
func TestIssueToken_ExpiredPriorTokenIsAccepted(t *testing.T) {
	signer := testSigner(t)
	delegationID := uuid.New()
	fs := &fakeStore{delegation: activeDelegation(delegationID, time.Now())}

	prior := priorToken(t, signer, delegationID, "")
	if _, err := signer.Verify(prior); err == nil {
		t.Fatal("the prior token is not expired: this test's premise is broken")
	}
	resp, err := NewServer(fs, denyAllPolicy(), testConfig(), signer).IssueToken(context.Background(),
		&IssueTokenRequest{DelegationId: delegationID.String(), TtlSeconds: 600, Token: prior})
	if err != nil {
		t.Fatalf("IssueToken() error = %v, want success", err)
	}
	if _, err := signer.Verify(resp.GetToken()); err != nil {
		t.Errorf("the re-issued token does not verify: %v", err)
	}
}

// Re-issuing can never loosen or move a key binding. Otherwise a stolen
// bound token, useless on its own, could be traded here for a bearer token
// or one bound to the thief's key.
func TestIssueToken_BoundPriorTokenKeepsItsBinding(t *testing.T) {
	signer := testSigner(t)
	delegationID := uuid.New()
	ownerJWK, ownerJKT := freshJWK(t)
	thiefJWK, _ := freshJWK(t)
	prior := priorToken(t, signer, delegationID, ownerJKT)

	issue := func(jwk *string) (*IssueTokenResponse, error) {
		fs := &fakeStore{delegation: activeDelegation(delegationID, time.Now())}
		return NewServer(fs, denyAllPolicy(), testConfig(), signer).IssueToken(context.Background(),
			&IssueTokenRequest{DelegationId: delegationID.String(), TtlSeconds: 600, Token: prior, DpopJwk: jwk})
	}

	if resp, err := issue(nil); resp != nil || err == nil {
		t.Fatalf("no JWK: got resp=%v err=%v, want a refusal (would downgrade to a bearer token)", resp, err)
	} else {
		wantCode(t, err, codes.PermissionDenied)
	}
	if resp, err := issue(&thiefJWK); resp != nil || err == nil {
		t.Fatalf("another key: got resp=%v err=%v, want a refusal (would rebind to the caller's key)", resp, err)
	} else {
		wantCode(t, err, codes.PermissionDenied)
	}

	resp, err := issue(&ownerJWK)
	if err != nil {
		t.Fatalf("same key: IssueToken() error = %v, want success", err)
	}
	claims, err := signer.Verify(resp.GetToken())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got, _ := tokenThumbprint(claims); got != ownerJKT {
		t.Errorf("re-issued token jkt = %q, want the original binding %q", got, ownerJKT)
	}
}

// An unbound token's holder already has a bearer credential, so letting it
// take a binding (the agent's bootstrap: bearer token from CreateDelegation,
// then a bound one) gives away nothing.
func TestIssueToken_UnboundPriorTokenMayTakeABinding(t *testing.T) {
	signer := testSigner(t)
	delegationID := uuid.New()
	jwk, jkt := freshJWK(t)
	fs := &fakeStore{delegation: activeDelegation(delegationID, time.Now())}

	resp, err := NewServer(fs, denyAllPolicy(), testConfig(), signer).IssueToken(context.Background(),
		&IssueTokenRequest{DelegationId: delegationID.String(), TtlSeconds: 600,
			Token: priorToken(t, signer, delegationID, ""), DpopJwk: &jwk})
	if err != nil {
		t.Fatalf("IssueToken() error = %v, want success", err)
	}
	claims, err := signer.Verify(resp.GetToken())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got, _ := tokenThumbprint(claims); got != jkt {
		t.Errorf("jkt = %q, want %q", got, jkt)
	}
}
